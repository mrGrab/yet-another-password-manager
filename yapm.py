#!/usr/bin/env python3

import csv
import logging
import sys
import click
from prettytable import from_csv
from cryptography.fernet import Fernet
from io import StringIO
from os import path
from datetime import datetime
from flask import Flask, jsonify, request, render_template, url_for, redirect, session, abort

logging.basicConfig()
logger = logging.getLogger(__name__)
STORAGE = "./data_storage"

class Encryptor(object):
	''' Encrypt/decrypt file and generate key for new one'''
	def __init__(self, password, file):
		self.key = password
		self.file = file

	def gen_key(self):
		key = Fernet.generate_key()
		logger.debug("New key has been generated")
		click.echo ("New password for storage has been generated\n")
		click.secho ("DON'T LOSE YOUR KEY. There is no option to restore ot change it", fg="red")
		click.secho (f"KEY: {key.decode()}\n", fg="red") 
		return (key)

	def encrypt(self, data):
		f = Fernet(self.key)
		encrypted = f.encrypt(data.encode())
		with open (self.file, 'wb') as enc_file:
			enc_file.write(encrypted)
		logger.debug("encrypted data has been writed to %s" % self.file)

	def decrypt(self):
		try:
			f = Fernet(self.key)
			with open(self.file, 'rb') as enc_file:
				encrypted = enc_file.read()
			return f.decrypt(encrypted).decode()
		except Exception as err:
			logger.debug(err)
			click.secho(f"Wrong password or unable to read {self.file}", fg="red")
			sys.exit(1)

class CSV():
	''' Manage encrypted data like cvs file '''
	def __init__(self, password, file):
		self.file = Encryptor(password, file)
		self.file_exists = path.isfile(file)
		if not self.file_exists:
			logger.debug("%s - doesn't exists" % file)
			self.file.key = self.file.gen_key()
			self.file.encrypt("")
			self.file_exists = True

	def write(self, data, remove=False):
		''' Write data in CSV format to file '''
		fieldnames = data.keys()
		cur_data = self.read()
		str_file = StringIO("")
		writer = csv.DictWriter(str_file, delimiter=',', lineterminator='\n', fieldnames=fieldnames, quoting=csv.QUOTE_NONNUMERIC)
		writer.writeheader()
		for row in cur_data:
			if row['Title'] != data['Title']:
				writer.writerow(row)
		if not remove:
			writer.writerow(data)
		self.file.encrypt(str_file.getvalue())

	def read(self):
		''' Read csv data from file '''
		result = []
		str_file = StringIO(self.file.decrypt())
		reader = csv.DictReader(str_file, delimiter=",")
		for row in reader:
			result.append(row)
		return(result)

	def raw_print(self):
		return self.file.decrypt()

class WebUi(object):
	"""WebUI for manage data in encrypted file """
	def __init__(self, port, filename):
		self.app = Flask(__name__)
		self.filename = filename
		self.password = None
		self.app.env = "Production"
		self.host = "0.0.0.0"
		self.port = port
		self.app.secret_key = b'\x8fL\xb1\x05\xb9\xa0\xe7<\x96L@\xf8\x17\xe1n '
		
	def run(self):
		self.add_routes()
		self.app.run(host=self.host, port=self.port, debug=False)

	def add_routes(self):
		@self.app.route('/')
		def home():
			if self.password and 'username' in session:
				return render_template('index.html.jinja')
			else:
				return redirect(url_for('logout'))	

		@self.app.route('/heartbeat')
		def  heartbeat():
			return jsonify({"status": "healthy"})

		@self.app.route('/login', methods=['GET', 'POST'])
		def login():
			# verify master key as password
			error = None
			if request.method == 'POST':
				self.password = request.form['password']
				session['username'] = request.form['username']
				try:
					self.file = CSV(self.password, self.filename)
					self.file.raw_print()
				except:
					error = 'Invalid password. Please try again.'
				else:
					return redirect(url_for('home'))
			return render_template('login.html.jinja', error=error)

		@self.app.route('/logout')
		def logout():
			# remove the username from the session if it's there
			session.pop('username', None)
			return redirect(url_for('login'))

		@self.app.route('/list', methods=['POST', 'GET'])
		def list():
			# return storage data as json
			if self.password and 'username' in session:
				if request.method == 'POST':
					return jsonify(self.file.read())
				else:
					abort(405)
			else:
				abort(401)

		@self.app.route('/crud', methods=['POST'])
		def crud():
			# Manage incoming data
			if self.password and 'username' in session:
				if request.method == 'POST':
					req_data = request.get_json(force=True)
					modified = datetime.now().strftime("%d-%m-%Y %X")
					data = {'Title': req_data["Title"],
							'Username': req_data["Username"],
							'Password': req_data[''],
							'URL': req_data["URL"],
							'Notes': req_data["Notes"],
							'Modified': str(modified)
							}
					try:
						self.file.write(data, remove=True if "Remove" in req_data else False)
					except:
						abort(500)
					else:
						return jsonify(data), 200
				else:
					abort(405)
			else:
				abort(401)


def get_password(filename, password=None):
	if path.isfile(filename) and password == None:
		return click.prompt("Please enter master key", hide_input=True) 
	elif not path.isfile(filename):
		click.echo(f"There is no {filename} file. Creating new one")		
		return ""
	else:
		return password

@click.group()
@click.option('--log', default="WARNING", type=str, show_default=True, 
				help='Set loglevel: DEBUG, INFO, WARNING, ERROR, CRITICAL')
def main(log):
	''' Application for store secrets and manage them '''
	logger.setLevel(log.upper())

@main.command()
@click.option('--filename', default=STORAGE, show_default=True, 
				help='File where we store data' )
@click.option('--password', default=None, hide_input=True,
				help='Master key for storage')
def show(filename, password):
	''' Print out data from file '''
	file = CSV(get_password(filename, password), filename)
	str_file = StringIO(file.raw_print())
	if str_file.getvalue():
		table = from_csv(str_file)
		table.align = "l"
		click.secho(str(table), fg="bright_blue")
	else:
		click.echo("Empty file, nothing to print")

@main.command()
@click.option('--filename', default=STORAGE, show_default=True, 
				help='File where we store data' )
@click.option('--password', default=None, hide_input=True,
				help='Master key for storage')
@click.option('--title', prompt=True, required=True,
				help='Title for your secret. Should be unique')
@click.option('--username', prompt=True, help="Type user name")
@click.option('--pwd', prompt=True, hide_input=True, help="Password for username")
@click.option('--url', prompt=True, help="URL to resource")
@click.option('--notes', prompt=True, help="Add any comments")
def add(filename, password, title, username, pwd, url, notes):
	''' Add new entry to storage '''
	file = CSV(get_password(filename, password), filename)
	modified = datetime.now().strftime("%d-%m-%Y %X")
	file.write({'Title': title,
			'Username': username,
			'Password': pwd,
			'URL': url,
			'Notes': notes,
			'Modified': str(modified)
			})

@main.command()
@click.option('--filename', default=STORAGE, show_default=True, 
				help='File where we store data' )
@click.option('--password', default=None, hide_input=True,
				help='Master key for storage')
@click.option('--title', prompt=True, required=True, help="Type user name")
def remove(filename, password, title):
	''' Remove some secret from file '''
	file = CSV(get_password(filename, password), filename)
	file.write({'Title': title,
			'Username': '',
			'Password': '',
			'URL': '',
			'Notes': '',
			'Modified': ''}, remove=True)

@main.command()
@click.option('--port', default=5000, type=int, show_default=True,
				help='Set port for webserver')
@click.option('--filename', default=STORAGE, show_default=True, 
				help='File where we store data' )
def webui(port, filename):
	''' Start webUI '''
	click.secho(f"\tStarting {__name__}", fg='green', bold=True)
	app = WebUi(port, filename)
	app.run()

if __name__ == '__main__':
	main()
