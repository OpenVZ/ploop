#include <Python.h>
#include <stdio.h>
#include "ploop.h"

#define ploop_di_object_t "ploop_di_object_t"

typedef struct {
	PyObject_HEAD
	struct ploop_disk_images_data *di;
} ploop_di_object;

#define ploop_copy_handle_object_t "ploop_copy_handle_object_t"
typedef struct {
	PyObject_HEAD
	struct ploop_copy_handle *h;
} ploop_copy_handle_object;


static int is_valid_object(PyObject *obj, const char *name)
{
	return (PyCObject_Check(obj) &&
			strcmp((char *)PyCObject_GetDesc(obj), name) == 0);
}

static int is_ploop_di_object(PyObject *obj)
{
	return is_valid_object(obj, ploop_di_object_t);
}

static int is_ploop_copy_handle_object(PyObject *obj)
{
	return is_valid_object(obj, ploop_copy_handle_object_t);
}

static PyObject *libploop_open_dd(PyObject *self, PyObject *args)
{
	int ret;
	char *ddxml;
	struct ploop_disk_images_data *di;

	if (!PyArg_ParseTuple(args, "s:libploop_open_dd", &ddxml)) {
		PyErr_SetString(PyExc_ValueError, "An incorrect ddxml");
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	ret = ploop_open_dd(&di, ddxml);
	Py_END_ALLOW_THREADS
	if (ret) {
		PyErr_SetString(PyExc_RuntimeError, "ploop_open_dd");
		return NULL;
	}

	return PyCObject_FromVoidPtrAndDesc(di, ploop_di_object_t, NULL);
}

static PyObject *libploop_close_dd(PyObject *self, PyObject *args)
{
	PyObject *py_di;
	struct ploop_disk_images_data *di;

	if (!PyArg_ParseTuple(args, "O:libploop_close_dd", &py_di) ||
			!is_ploop_di_object(py_di))
		return NULL;

	di = ((ploop_di_object *)py_di)->di;

	Py_BEGIN_ALLOW_THREADS
	ploop_close_dd(di);
	Py_END_ALLOW_THREADS

	Py_RETURN_NONE;
}

static PyObject *libploop_copy_init(PyObject *self, PyObject *args)
{
	int ret;
	PyObject *py_di;
	struct ploop_disk_images_data *di;
	struct ploop_copy_handle *h;
	struct ploop_copy_param param = {};

	if (!PyArg_ParseTuple(args, "Ok:libploop_copy_init", &py_di, &param.ofd) ||
			!is_ploop_di_object(py_di))
	{
		PyErr_SetString(PyExc_ValueError, "An incorrect parameter");
		return NULL;
	}

	di = ((ploop_di_object *)py_di)->di;

	Py_BEGIN_ALLOW_THREADS
	ret = ploop_copy_init(di, &param, &h);
	Py_END_ALLOW_THREADS
	if (ret) {
		PyErr_SetString(PyExc_RuntimeError, ploop_get_last_error());
		return NULL;
	}

	return PyCObject_FromVoidPtrAndDesc(h, ploop_copy_handle_object_t, NULL);
}

static PyObject *libploop_copy_start(PyObject *self, PyObject *args)
{
	int ret;
	PyObject *py_h;
	struct ploop_copy_handle *h;
	struct ploop_copy_stat stat = {};

	if (!PyArg_ParseTuple(args, "O:libploop_copy_start", &py_h) ||
			!is_ploop_copy_handle_object(py_h))
	{
		PyErr_SetString(PyExc_ValueError, "An incorrect parameter");
		return NULL;
	}

	h = ((ploop_copy_handle_object *)py_h)->h;

	Py_BEGIN_ALLOW_THREADS
	ret = ploop_copy_start(h, &stat);
	Py_END_ALLOW_THREADS
	if (ret) {
		PyErr_SetString(PyExc_RuntimeError, ploop_get_last_error());
		return NULL;
	}

	return PyLong_FromLong((long)ret);
}

static PyObject *libploop_copy_next_iteration(PyObject *self, PyObject *args)
{
	int ret;
	PyObject *py_h;
	struct ploop_copy_handle *h;
	struct ploop_copy_stat stat = {};

	if (!PyArg_ParseTuple(args, "O:libploop_copy_start", &py_h) ||
			!is_ploop_copy_handle_object(py_h))
	{
		PyErr_SetString(PyExc_ValueError, "An incorrect parameter");
		return NULL;
	}

	h = ((ploop_copy_handle_object *)py_h)->h;

	Py_BEGIN_ALLOW_THREADS
	ret = ploop_copy_next_iteration(h, &stat);
	Py_END_ALLOW_THREADS
	if (ret) {
		PyErr_SetString(PyExc_RuntimeError, ploop_get_last_error());
		return NULL;
	}

	return PyLong_FromLong((long) stat.xferred);
}

static PyObject *libploop_copy_stop(PyObject *self, PyObject *args)
{
	int ret;
	PyObject *py_h;
	struct ploop_copy_handle *h;

	if (!PyArg_ParseTuple(args, "O:libploop_copy_start", &py_h) ||
			!is_ploop_copy_handle_object(py_h))
	{
		PyErr_SetString(PyExc_ValueError, "An incorrect parameter");
		return NULL;
	}

	h = ((ploop_copy_handle_object *)py_h)->h;

	Py_BEGIN_ALLOW_THREADS
	ret = ploop_copy_stop(h);
	Py_END_ALLOW_THREADS
	if (ret) {
		PyErr_SetString(PyExc_RuntimeError, ploop_get_last_error());
		return NULL;
	}

	return PyLong_FromLong((long)ret);
}

static PyObject *libploop_copy_deinit(PyObject *self, PyObject *args)
{
	PyObject *py_h;
	struct ploop_copy_handle *h;

	if (!PyArg_ParseTuple(args, "O:libploop_copy_start", &py_h) ||
			!is_ploop_copy_handle_object(py_h))
	{
		PyErr_SetString(PyExc_ValueError, "An incorrect parameter");
		return NULL;
	}

	h = ((ploop_copy_handle_object *)py_h)->h;

	Py_BEGIN_ALLOW_THREADS
	ploop_copy_deinit(h);
	Py_END_ALLOW_THREADS

	Py_RETURN_NONE;
}

static PyObject *libploop_start_receiver(PyObject *self, PyObject *args)
{
	int ret;
	struct ploop_copy_receive_param param = {};

	if (!PyArg_ParseTuple(args, "sk:libploop_copy_init", &param.file, &param.ifd)) {
		PyErr_SetString(PyExc_ValueError, "An incorrect parameter");
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	ret = ploop_copy_receiver(&param);
	Py_END_ALLOW_THREADS
	if (ret) {
		PyErr_SetString(PyExc_RuntimeError, ploop_get_last_error());
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyMethodDef PloopMethods[] = {
	{ "open_dd", libploop_open_dd, METH_VARARGS, "Open DiskDescriptor.xml" },
	{ "close_dd", libploop_close_dd, METH_VARARGS, "Close DiskDescriptor.xml" },
	{ "copy_init", libploop_copy_init, METH_VARARGS, "Init ploop copy handle" },
	{ "copy_start", libploop_copy_start, METH_VARARGS, "Make initial ploop copy" },
	{ "copy_next_iteration", libploop_copy_next_iteration, METH_VARARGS, "Copy changed blocks" },
	{ "copy_stop", libploop_copy_stop, METH_VARARGS, "Final copy after CT freeze" },
	{ "copy_deinit", libploop_copy_deinit, METH_VARARGS, "Free ploop copy handle" },
	{ "start_receiver", libploop_start_receiver, METH_VARARGS, "Start ploop copy receiver" },
	{ NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC initlibploopapi(void)
{
	PyObject *m;

	m = Py_InitModule("libploopapi", PloopMethods);
	if (m == NULL)
		return;
}
