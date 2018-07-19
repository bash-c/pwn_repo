#!/usr/bin/python2
import os, sys, time
import subprocess
from threading import Timer

TIME = 5

class MyTimer():
	timer=None
	def __init__(self):
		self.timer = Timer(TIME, self.dispatch, args=[])
		self.timer.start()
	def dispatch(self):
		print 'program is not responding... something must be wrong :('
		os._exit(0)

def pwn( payload ):
	p = subprocess.Popen('./wtf', stdin=subprocess.PIPE, stdout=subprocess.PIPE)
	p.stdin.write( payload )
	output = p.stdout.readline()
	return output

if __name__ == '__main__':
	print '''
	---------------------------------------------------
	-              Shall we play a game?              -
	---------------------------------------------------
	
	Hey~, I'm a newb in this pwn(?) thing...
	I'm stuck with a very easy bof task called 'wtf'
	I think this is quite easy task, however my
	exploit payload is not working... I don't know why :(
	I want you to help me out here.
	please check out the binary and give me payload
	let me try to pwn this with yours.

	                            - Sincerely yours, newb
	'''
	sys.stdout.flush()
	time.sleep(1)

	try:
		sys.stdout.write('payload please : ')
		sys.stdout.flush()		
		payload = raw_input()
		payload = payload.decode('hex')

		print 'thanks! let me try if your payload works...'
		sys.stdout.flush()

		time.sleep(1)
		MyTimer()
		result = pwn( payload )
		if len(result) == 0:
			print 'your payload sucks! :('
			print 'I thought you were expert... what a shame :P'
			sys.stdout.flush()
			os._exit(0)

		print 'hey! your payload got me this : {0}\n'.format(result)
		print 'I admit, you are indeed an expert :)'
		sys.stdout.flush()
	except:
		print 'please give your payload in hex encoded format..'
		sys.stdout.flush()
		os._exit(0)

	sys.stdout.flush()
	os._exit(0)

