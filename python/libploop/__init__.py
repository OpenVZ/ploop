import libploopapi
import threading

class ploopcopy():
	def __init__(self, ddxml, fd):
		self.di = libploopapi.open_dd(ddxml)
		self.h = libploopapi.copy_init(self.di, fd)

	def __del__(self):
		if self.h:
			libploopapi.copy_deinit(self.h)
		if self.di:
			libploopapi.close_dd(self.di)

	def copy_start(self):
		return libploopapi.copy_start(self.h)

	def copy_next_iteration(self):
		return libploopapi.copy_next_iteration(self.h)

	def copy_stop(self):
		ret = libploopapi.copy_stop(self.h)
		libploopapi.copy_deinit(self.h)
		self.h = None
		return ret;

class ploopcopy_receiver():
	def __init__(self, fname, fd):
		libploopapi.start_receiver(fname, fd);

class ploopcopy_thr_receiver(threading.Thread):
	def __init__(self, fname, fd):
		threading.Thread.__init__(self)
		self.__fname = fname
		self.__fd = fd

	def run(self):
		libploopapi.start_receiver(self.__fname, self.__fd);
