#!/usr/bin/python
import libploop
import shutil
import io
import os
import socket
import time
import subprocess as sp
import unittest
import hashlib

sleep_sec = 3

def hashfile(afile, hasher, blocksize=65536):
	buf = afile.read(blocksize)
	while len(buf) > 0:
		hasher.update(buf)
		buf = afile.read(blocksize)
	print (hasher.hexdigest())
	return hasher.hexdigest()


def start_image_filller():
	pid = os.fork()
	if pid == 0:
		os.execl('/bin/dd',  'dd', 'if=/dev/urandom', "of=/dev/ploop0", 'bs=4096', 'count=131072', 'oflag=direct')
		os._exit(1)
	else:
		print "Start filler pid=%d" % pid
		time.sleep(sleep_sec)
		return pid

def start_pcopy_receiver(fname, fd):
	print "Start receiver"
	t = libploop.ploopcopy_thr_receiver(fname, fd)
	t.start()
	return t

def get_storage():
	return '/vz/test'

def get_image():
	return os.path.join(get_storage(), "test.hds")

def get_ddxml():
	return os.path.join(get_storage(), 'DiskDescriptor.xml')

def get_mnt_dir():
	return '_'.join([get_storage(), "mnt"])

def ploop_create(img):
	ret = sp.call(["ploop", "init", "-s10g", img])
	if ret != 0:
		raise Exception("failed to create image")

def ploop_mount(ddxml):
	ret = sp.call(["ploop", "mount", "-d/dev/ploop0", ddxml])
	if ret != 0:
		raise Exception("failed to mount image")

def ploop_umount(ddxml):
	return sp.call(["ploop", "umount", "-d/dev/ploop0"])

def do_ploop_copy(ddxml, fd):

	print "do_ploop_copy"
	ploop_mount(ddxml)
	pc = libploop.ploopcopy(ddxml, fd);

	pid = start_image_filller()

	print "Start copy"
	pc.copy_start()

	for n in range(0, 10):
		print "Iter:",  n
		transferred = pc.copy_next_iteration()
		print "transferred:", transferred
		time.sleep(sleep_sec)

	print "Wait filler %d" % pid
	os.kill(pid, 15)
	os.waitpid(pid, 0)

	print "Stop sopy"
	pc.copy_stop()
	ploop_umount(ddxml)


class testPcopy(unittest.TestCase):
	def setUp(self):
		if not os.path.exists('/dev/ploop0'):
			sp.call(['mknod', '/dev/ploop0', 'b', '182', '0'])

		if os.path.exists(get_ddxml()):
			ploop_umount(get_ddxml())
			shutil.rmtree(get_storage())

		if not os.path.exists(get_storage()):
			os.mkdir(get_storage())

		if not os.path.exists(get_mnt_dir()):
			os.mkdir(get_mnt_dir())

		ploop_create(get_image())
		self.out = os.path.join(get_storage(), "out.hds")
		self.ddxml = get_ddxml()

	def tearDown(self):
		print "tearDown"
		if os.path.exists(get_ddxml()):
			ploop_umount(get_ddxml())
			shutil.rmtree(get_storage())

	def test_aremote(self):
		print "Start remote"

		parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

		self.rcv_thr = start_pcopy_receiver(self.out, child.fileno())

		do_ploop_copy(self.ddxml, parent.fileno())

		src = hashfile(open(get_image(), 'rb'), hashlib.md5())
		dst = hashfile(open(self.out, 'rb'), hashlib.md5())

		self.assertEqual(src, dst)

	def test_local(self):
		print "Start local"

		f = open(self.out, 'wb')

		do_ploop_copy(self.ddxml, f.fileno())

		src = hashfile(open(get_image(), 'rb'), hashlib.md5())
		dst = hashfile(open(self.out, 'rb'), hashlib.md5())

		self.assertEqual(src, dst)

if __name__ == '__main__':
	unittest.main()
