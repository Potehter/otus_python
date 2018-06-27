#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field(object):
    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable

class CharField(Field):
    def validate(self, value):
        if not isinstance(value, str):
            raise ValueError


class ArgumentsField(Field):
    def validate(self, value):
        if not isinstance(value, dict):
            raise ValueError


class EmailField(CharField):
    def validate(self, value):
        if isinstance(value, str) and '@' in value:
            pass
        else:
            raise ValueError


class PhoneField(Field):
    def validate(self, value):
        if not isinstance(value, str):
            raise ValueError


class DateField(Field):
    def validate(self, value):
        try:
            return datetime.datetime.strptime(value, '%d.%m.%Y')
        except TypeError:
            raise ValueError


class BirthDayField(Field):
    def validate(self, value):
        value = super(BirthDayField, self).clean(value)
        delta70years = datetime.timedelta(days=70*365.25)
        if (datetime.datetime.now() - value) > delta70years:
            raise ValueError
        return value


class GenderField(Field):
    def validate(self, value):
        if value not in GENDERS:
            raise ValueError
        return value


class ClientIDsField(Field):
    def clean(self, value):
        if not isinstance(value, list):
            raise ValueError
        return value


class Request(object):
    def __init__(self, **kwargs):
        self.errors = {}
        self.base_fields = []
        self.empty_fields = []
        self.fields = {}
        print kwargs.items()
        for field_name, value in kwargs.items():

            setattr(self, field_name, value)
            self.base_fields.append(field_name)
            self.fields[field_name] = value
            if value in ('', [], {}):
                self.empty_fields.append(field_name)

    def validate(self):
        print self.fields
        for name, field in self.fields.items():
            if name not in self.base_fields:
                if field.required:
                    self.errors[name] = 'This field is requiredir d'
                    continue
            if name in self.empty_fields and not field.nullable:
                self.errors[name] = 'This field has to be filled'
                continue
            value = getattr(self, name)
            try:
                field.validate(value)
            except ValueError as e:
                self.errors[name] = e.message

class ClientsInterestsRequest(Request):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(Request):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)


class MethodRequest(Request):
    print Request
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


class ClientsInterestsProcess(object):
    def process(self, request, context):
        print 'in process of clients'
        request = ClientsInterestsRequest(**request.arguments)
        request.validate()
        score = 100
        return {"score": score}, OK


class OnlineScoreProcess(object):
    def process(self, request, context):
        print 'in process of score'
        request = OnlineScoreRequest(**request.arguments)
        request.validate()


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    response, code = None, 580
    handlers = {
        "clients_interests": ClientsInterestsProcess,
        "online_score": OnlineScoreProcess
    }
    try: 
        method_request = MethodRequest(**request['body'])
    except:
        return 'Error in method handler'
    print method_request
    handler = handlers[method_request.method]()
    print handler
    return handler.process(method_request, ctx)
    #if online_score
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            print 'in if request'
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            print 'after logging'
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception, e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        print 'after if'
        self.send_response(code)
        print 'after send response'
        self.send_header("Content-Type", "application/json")
        print 'after send header'
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return

if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
