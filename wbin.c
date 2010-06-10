/*
 * Copyright 2005-2010 Slide, Inc.
 * All Rights Reserved
 * 
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission
 * notice appear in supporting documentation, and that the name of
 * Slide not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior
 * permission.
 * 
 * SLIDE DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN
 * NO EVENT SHALL SLIDE BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <Python.h>
#include <unicodeobject.h>
#include <netinet/in.h>
#if defined(__linux__)
	#include <byteswap.h>
	#include <endian.h>
#endif

PyDoc_STRVAR(wbin_module_documentation,
	     "Provide encoding and decoding functions for a speed/CPU "
	     "optimized\n binary string representation of basic python "
	     "types.\n");

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

#define INIT_BUFFER_LEN   0x1000
#define DEFAULT_MAX_DEPTH 0x1000
#define DEFAULT_MAX_RUN   0x8000

struct serial_buffer {
	/*
	 * buffer/position/length information
	 */
	char *buf;
	int   off;
	int   len;
	/*
	 * yield function/period/last information
	 */
	PyObject *func;
	PyObject *args;
	int       size;
	int       last;
};

#define TYPE_NULL   0x0
#define TYPE_INT    0x1
#define TYPE_STRING 0x2
#define TYPE_LIST   0x4
#define TYPE_DICT   0x5
#define TYPE_LONG   0x6
#define TYPE_UTF8   0x7
#define TYPE_DOUBLE 0x8
#define TYPE_TUPLE  0x9
#define TYPE_LONGER 0xA
#define TYPE_PICKLE 0xB

#define TYPE_CMD 666
#define TYPE_RESPONSE 667
#define TYPE_PUSH 668

#if defined(__linux__)
	#if __BYTE_ORDER == __LITTLE_ENDIAN
	#define htonll(x) bswap_64(x)
	#define ntohll(x) bswap_64(x)
	#else
	#define htonll(x) (x)
	#define ntohll(x) (x)
	#endif
#endif
#if defined(__APPLE__)
	#include <libkern/OSByteOrder.h>
	#define htonll(x) OSSwapHostToBigInt64(x)
	#define ntohll(x) OSSwapBigToHostInt64(x)
#endif

#if PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION == 4
typedef int Py_ssize_t ;
#endif

static PyObject *cpickle_str;
static PyObject *cploads_str;
static PyObject *cpdumps_str;
static PyObject *empty_tuple;

static PyObject *cpick  = NULL;
static int utf8_support = 1;
static int wls_on = 1;
static int max_depth    = DEFAULT_MAX_DEPTH;

struct whitelist_entry {
	PyObject *mod;
	PyObject *cls;
	char     *mname;
	char     *cname;
};

static struct whitelist_entry whitelist[] = {
	{NULL, NULL, "decimal", "Decimal"},
	{NULL, NULL, NULL, NULL}
};

static int _check_space(struct serial_buffer *buffer, int space)
{
	if ((buffer->len - buffer->off) < space) {
		PyErr_Format(PyExc_SystemError,
			     "insufficient data <%d> at <%d> of <%d>",
			     space, buffer->off, buffer->len);
		return -EINVAL;
	}

	return 0;
}

#ifdef USED_SOMEWHERE
static int _check_encode(char *str, int size)
{
	int i;

	for (i = 0; i < size/4; i++)
		if (0x80808080 & ((unsigned int *)str)[i])
			return 1;

	for (i *= 4; i < size; i++)
		if (0x80 & str[i])
			return 1;

	return 0;
}
#endif

static int _check_yield(struct serial_buffer *b)
{
	PyObject *result = NULL;
	PyObject *args;
	int i = 0;

	if ((b->off - b->last) < b->size)
		return 0;
	/*
	 * allocate call argument tuple of size N + 1. Where N
	 * is the size of the user supplied tuple, the extra slot
	 * contains the current offset as feedback for the user.
	 */
	args = PyTuple_New(PyTuple_GET_SIZE(b->args) + 1);
	/*
	 * Place the current offset into slot 0, the single reference
	 * to the new integer object will be decremented when the arg
	 * tuple is dereferenced and deallocated.
	 */
	PyTuple_SET_ITEM(args, i++, PyInt_FromLong(b->off));
	/*
	 * Link the objects in the user supplied arguments tuple into
	 * the new tuple. Do not incremenet the reference count since
	 * after the call we NULL out the entries w/o a decrement.
	 */
	for (; i < PyTuple_GET_SIZE(args); i++)
		PyTuple_SET_ITEM(args, i, PyTuple_GET_ITEM(b->args, i-1));
	/*
	 * call user supplied callback
	 */
	result = PyObject_Call(b->func, args, NULL);
	/*
	 * NULL out the entries for the user supplied arguments, and
	 * derefernce the local arguments tuple.
	 */
	for (i = 1; i < PyTuple_GET_SIZE(args); i++)
		PyTuple_SET_ITEM(args, i, NULL);

	Py_DECREF(args);
	/*
	 * process result
	 */
	if (!result)
		return -EINVAL;

	Py_DECREF(result);
	b->last = b->off;
	return 0;
}

static void _deserialize_error(struct serial_buffer *b)
{
	/*
	 * check if the current error is a memory error and include
	 * information about our buffer.
	 */
	if (PyErr_Occurred() != PyExc_MemoryError)
		return;

	PyErr_Format(PyExc_MemoryError,
		     "allocation failure. length <%d> offset <%d>",
		     b->len, b->off);
	return;
}		       

static int _get_size(struct serial_buffer *b)
{
	int size;

	if (_check_space(b, sizeof(uint32_t))) {
		PyErr_Format(PyExc_MemoryError, 
			     "no size available at <%d> of <%d>",
			     b->off, b->len);
		return -1;
	}

	size = ntohl(*(uint32_t *)(b->buf + b->off));
	b->off += sizeof(uint32_t);

	if (size > (b->len - b->off)) {
		PyErr_Format(PyExc_MemoryError,
			     "Unreasonable element size <%d> at offset <%ld>",
			     size, b->off - sizeof(uint32_t));
		return -1;
	}

	return size;
}

static PyObject *_deserialize_object(struct serial_buffer *b)
{
	PyObject *output = NULL;
	PyObject *loads;
	PyObject *value;
	int result = 0;
	int size;

	size = _get_size(b);
	if (0 > size)
		goto err_load;

	result = _check_space(b, size);
	if (result)
		goto err_load;

	loads = PyObject_GetAttr(cpick, cploads_str);
	if (!loads)
		goto err_load;

	value = PyString_FromStringAndSize((b->buf + b->off), size);
	if (!value)
		goto err_data;

	b->off += size;

	output = PyObject_CallFunction(loads, "O", value);

	Py_DECREF(value);
err_data:
	Py_DECREF(loads);
err_load:
	return output;
}

static PyObject *_deserialize(struct serial_buffer *b, int intern)
{
	PyObject *output = NULL;
	PyObject *value;
	PyObject *key;
	char error_str[128];
	int result;
	int type;
	int size;
	int i;

	if (!b) {
		PyErr_SetString(PyExc_SystemError, "missing buffer object");
		return NULL;
	}

	if (b->func) {
		if (_check_yield(b))
			return NULL;
	}

	result = _check_space(b, sizeof(uint16_t));
	if (result)
		return NULL;

	type = ntohs(*(uint16_t *)(b->buf + b->off));
	b->off += sizeof(uint16_t);

	switch (type) {
	case TYPE_INT:
		result = _check_space(b, sizeof(uint32_t));
		if (result)
			break;
		output = PyInt_FromLong((int32_t)ntohl(*(uint32_t *)(b->buf + b->off)));
		b->off += sizeof(uint32_t);
		break;
	case TYPE_LONG:
		result = _check_space(b, sizeof(uint64_t));
		if (result)
			break;
#if !defined(__APPLE__)
		output = PyInt_FromLong(ntohll(*(uint64_t *)(b->buf + b->off)));
#else
		output = PyLong_FromLongLong(ntohll(*(uint64_t *)(b->buf + b->off)));
#endif
		b->off += sizeof(uint64_t);
		break;
	case TYPE_LONGER:
		size = _get_size(b);
		if (0 > size)
			break;
		result = _check_space(b, size);
		if (result)
			break;

		output = _PyLong_FromByteArray(
			(unsigned char *)(b->buf + b->off), size, 0, 1);
		b->off += size;
		break;
	case TYPE_DOUBLE:
		result = _check_space(b, sizeof(double));
		if (result)
			break;
		output = PyFloat_FromDouble(*(double *)(b->buf + b->off));
		b->off += sizeof(double);
		break;
	case TYPE_STRING:
		size = _get_size(b);
		if (0 > size)
			break;
		result = _check_space(b, size);
		if (result)
			break;

		output = PyString_FromStringAndSize((b->buf + b->off), size);
		if (intern)
			PyString_InternInPlace(&output);

		b->off += size;
		break;
	case TYPE_UTF8:
		size = _get_size(b);
		if (0 > size)
			break;
		result = _check_space(b, size);
		if (result)
			break;

		output = PyUnicode_DecodeUTF8((b->buf + b->off), size, "strict");
		b->off += size;
		break;
	case TYPE_LIST:
		size = _get_size(b);
		if (0 > size)
			break;

		output = PyList_New(size);
		if (!output)
			break;

		for (i = 0; i < size; i++) {
			value = _deserialize(b, 0);
			if (!value)
				break;

			result = PyList_SetItem(output, i, value);
			if (result)
				/*
				 * SetItem decrements value refcnt on error
				 * and does not increase it on success.
				 */
				break;
		}

		if (size > i) {
			Py_DECREF(output);
			output = NULL;
		}
		break;
	case TYPE_DICT:
		size = _get_size(b);
		if (0 > size)
			break;

		output = PyDict_New();
		if (!output)
			break;

		while (size) {
			key = _deserialize(b, 1);
			if (!key)
				break;
			value = _deserialize(b, 0);
			if (!value) {
				Py_DECREF(key);
				break;
			}
			result = PyDict_SetItem(output, key, value);
			Py_DECREF(value);
			Py_DECREF(key);
			if (result)
				break;

			size--;
		}
		if (size > 0) {
			Py_DECREF(output);
			output = NULL;
		}
		break;
	case TYPE_TUPLE:
		size = _get_size(b);
		if (0 > size)
			break;

		output = PyTuple_New(size);
		if (!output)
			break;

		for (i = 0; i < size; i++) {
			value = _deserialize(b, 0);
			if (!value)
				break;
			result = PyTuple_SetItem(output, i, value);
			if (result)
				/*
				 * SetItem decrements value refcnt on error
				 * and does not increase it on success.
				 */
				break;
		}

		if (size > i) {
			Py_DECREF(output);
			output = NULL;
		}
		break;
	case TYPE_NULL:
		Py_INCREF(Py_None);
		output = Py_None;
		break;
	case TYPE_PICKLE:
		output = _deserialize_object(b);
		break;
	default:
		sprintf(error_str, "Unhandled type: <%d>", type);
		PyErr_SetString(PyExc_TypeError, error_str);
		break;
	}

	return output;
}

static int _check_size(struct serial_buffer *buffer, int size)
{
	char *new;

	while ((buffer->len - buffer->off) < (size + sizeof(uint16_t))) {
		new = realloc(buffer->buf, (buffer->len * 2));
		if (!new) {
			PyErr_Format(PyExc_MemoryError,
				     "failed to reallocate buffer to <%d>",
				     buffer->len * 2);
			return -ENOMEM;
		}

		buffer->buf = new;
		buffer->len = buffer->len * 2;
	}

	return 0;
}

static int _copy_string
(
	struct serial_buffer *b,
	const char *input_string,
	int input_size,
	short type
)
{
	int result;

	result = _check_size(b, input_size + sizeof(uint32_t));
	if (result)
		return result;

	*(uint16_t *)(b->buf + b->off) = htons(type);
	b->off += sizeof(uint16_t);
	*(uint32_t *)(b->buf + b->off) = htonl(input_size);
	b->off += sizeof(uint32_t);

	memcpy((b->buf + b->off), input_string, input_size);
	b->off += input_size;
	return 0;
}

static int _check_whitelist(PyObject *input)
{
	struct whitelist_entry *entry;

	if (!wls_on)
		return 0;

	for (entry = whitelist; entry->cls; entry++) {
		if (PyObject_IsInstance(input, entry->cls))
			return 0;
	}

	return -EINVAL;
}

static int _serialize_object(PyObject *input, struct serial_buffer *b, int dp)
{
	char error_str[128];
	PyObject *dumps;
	PyObject *value;
	int result = 0;

	if (_check_whitelist(input)) {
		sprintf(error_str, "Unlisted type: <%s>",
			input->ob_type->tp_name);
		PyErr_SetString(PyExc_TypeError, error_str);

		result = -EINVAL;
		goto err_dump;
	}

	dumps = PyObject_GetAttr(cpick, cpdumps_str);
	if (!dumps) {
		result = -EINVAL;
		goto err_dump;
	}

	value = PyObject_CallFunction(dumps, "O", input);
	if (!value) {
		result = -EINVAL;
		goto err_call;
	}

	result = _copy_string(b,
			      PyString_AS_STRING(value),
			      PyString_GET_SIZE(value),
			      TYPE_PICKLE);

	Py_DECREF(value);
err_call:
	Py_DECREF(dumps);
err_dump:
	return result;
}

static int _serialize(PyObject *input, struct serial_buffer *b, int dp)
{
	char error_str[128];
	PyObject *value;
	PyObject *key;
	long i;
	long long item;
	int result;

	if (max_depth < dp++) {
		PyErr_Format(PyExc_SystemError, 
			     "max recursion depth <%d> exceeded", max_depth);
		return -EINVAL;
	}

	if (!input) {
		PyErr_SetString(PyExc_SystemError, "missing input object");
		return -EINVAL;
	}
	if (!b) {
		PyErr_SetString(PyExc_SystemError, "missing buffer object");
		return -EINVAL;
	}

	if (b->func) {
		result = _check_yield(b);
		if (result)
			return result;
	}

	if (PyInt_Check(input)) {
		item = PyInt_AS_LONG(input);

		if (item > INT_MAX || item < INT_MIN) {
			result = _check_size(b, sizeof(uint64_t));
			if (result)
				return result;

			*(uint16_t *)(b->buf + b->off) = htons(TYPE_LONG);
			b->off += sizeof(uint16_t);
			*(uint64_t *)(b->buf + b->off) = htonll(item);
			b->off += sizeof(uint64_t);

			goto done;
		}
		else {
			result = _check_size(b, sizeof(uint32_t));
			if (result)
				return result;

			*(uint16_t *)(b->buf + b->off) = htons(TYPE_INT);
			b->off += sizeof(uint16_t);
			*(uint32_t *)(b->buf + b->off) = htonl(item);
			b->off += sizeof(uint32_t);

			goto done;
		}
	}

	if (PyLong_Check(input)) {
		item = PyLong_AsLongLong(input);
		if (item == -1 && PyErr_Occurred()) {
			PyErr_Clear();

			i = _PyLong_NumBits(input) + 1; /* include sign bit */
			i = i/8 + MIN(i%8, 1); /* byte count rounded up */

			result = _check_size(b, sizeof(uint32_t) + i);
			if (result)
				return result;

			*(uint16_t *)(b->buf + b->off) = htons(TYPE_LONGER);
			b->off += sizeof(uint16_t);
			*(uint32_t *)(b->buf + b->off) = htonl(i);
			b->off += sizeof(uint32_t);

			result = _PyLong_AsByteArray(
				(PyLongObject *)input,
				(unsigned char *)(b->buf + b->off),
				(size_t)i, 0, 1);
			if (result)
				return result;

			b->off += i;
			goto done;
		}
		else {
			result = _check_size(b, sizeof(uint64_t));
			if (result)
				return result;

			*(uint16_t *)(b->buf + b->off) = htons(TYPE_LONG);
			b->off += sizeof(uint16_t);
			*(uint64_t *)(b->buf + b->off) = htonll(item);
			b->off += sizeof(uint64_t);

			goto done;
		}
	}

	if (PyString_Check(input)) {
		result = _copy_string(b,
				      PyString_AS_STRING(input),
				      PyString_GET_SIZE(input),
				      TYPE_STRING);
		if (result)
			return result;

		goto done;
	}

	if (PyUnicode_Check(input)) {
		value = PyUnicode_AsUTF8String(input);
		if (!value)
			return -EINVAL;

		result = _copy_string(b,
				      PyString_AS_STRING(value),
				      PyString_GET_SIZE(value),
				      utf8_support ? TYPE_UTF8 : TYPE_STRING);
		Py_DECREF(value);

		if (result)
			return result;

		goto done;
	}

	if (PyList_Check(input)) {
		result = _check_size(b, sizeof(uint32_t));
		if (result)
			return result;

		*(uint16_t *)(b->buf + b->off) = htons(TYPE_LIST);
		b->off += sizeof(uint16_t);
		*(uint32_t *)(b->buf + b->off) = htonl(PyList_GET_SIZE(input));
		b->off += sizeof(uint32_t);

		for (i = 0; i < PyList_GET_SIZE(input); i++) {
			result = _serialize(PyList_GET_ITEM(input, i), b, dp);
			if (result)
				return result;
		}

		goto done;
	}

	if (PyDict_Check(input)) {
		Py_ssize_t j = 0;

		result = _check_size(b, sizeof(uint32_t));
		if (result)
			return result;

		*(uint16_t *)(b->buf + b->off) = htons(TYPE_DICT);
		b->off += sizeof(uint16_t);
		*(uint32_t *)(b->buf + b->off) = htonl(PyDict_Size(input));
		b->off += sizeof(uint32_t);

		while (PyDict_Next(input, &j, &key, &value)) {
			result = _serialize(key, b, dp);
			if (result)
				return result;
			result = _serialize(value, b, dp);
			if (result)
				return result;
		}

		goto done;
	}

	if (Py_None == input) {
		result = _check_size(b, 0);
		if (result)
			return result;

		*(uint16_t *)(b->buf + b->off) = htons(TYPE_NULL);
		b->off += sizeof(uint16_t);

		goto done;
	}

	if (PyFloat_Check(input)) {
		result = _check_size(b, sizeof(double));
		if (result)
			return result;

		*(uint16_t *)(b->buf + b->off) = htons(TYPE_DOUBLE);
		b->off += sizeof(uint16_t);
		*(double *)(b->buf + b->off) = PyFloat_AS_DOUBLE(input);
		b->off += sizeof(double);

		goto done;
	}

	if (PyTuple_Check(input)) {
		result = _check_size(b, sizeof(uint32_t));
		if (result)
			return result;

		*(uint16_t *)(b->buf + b->off) = htons(TYPE_TUPLE);
		b->off += sizeof(uint16_t);
		*(uint32_t *)(b->buf + b->off) = htonl(PyTuple_GET_SIZE(input));
		b->off += sizeof(uint32_t);

		for (i = 0; i < PyTuple_GET_SIZE(input); i++) {
			result = _serialize(PyTuple_GET_ITEM(input, i), b, dp);
			if (result)
				return result;
		}

		goto done;
	}

	if (cpick) {
		result = _serialize_object(input, b, dp);
		if (result)
			return result;

		goto done;
	}

	sprintf(error_str, "Unhandled type: <%s>",
		input->ob_type->tp_name);
	PyErr_SetString(PyExc_TypeError, error_str);
	return -EINVAL;
done:
	return 0;
}



static PyObject *py_serialize(PyObject *self, PyObject *args)
{
	struct serial_buffer buffer;
	PyObject *input;
	PyObject *output;
	PyObject *yield = NULL;
	PyObject *yargs = empty_tuple;
	int length = DEFAULT_MAX_RUN;
	int result;

	result = PyArg_ParseTuple(args, "O|OO!i", 
				  &input, &yield,
				  &PyTuple_Type, &yargs,
				  &length);
	if (!result)
		return NULL;

	if (yield && !PyCallable_Check(yield)) {
		PyErr_Format(PyExc_TypeError,
			     "'%s' object not callable",
			     yield->ob_type->tp_name);
		return NULL;
	}

	buffer.len  = INIT_BUFFER_LEN;
	buffer.off  = 0;
	buffer.buf  = malloc(buffer.len);
	buffer.func = yield;
	buffer.size = length;
	buffer.last = 0;
	buffer.args = yargs;

	if (!buffer.buf) {
		PyErr_Format(PyExc_MemoryError,
			     "failed to allocate buffer <%d>", buffer.len);
		return NULL;
	}

	result = _serialize(input, &buffer, 0);
	if (result)
		output = NULL;
	else
		output = PyString_FromStringAndSize(buffer.buf, buffer.off);

	free(buffer.buf);
	return output;
}

static PyObject *py_deserialize(PyObject *self, PyObject *args)
{
	struct serial_buffer buffer;
	PyObject *output;
	PyObject *input;
	PyObject *yield = NULL;
	PyObject *yargs = empty_tuple;
	int length = DEFAULT_MAX_RUN;
	int result;

	result = PyArg_ParseTuple(args, "O!|OO!i",
				  &PyString_Type, (PyObject *)&input, &yield,
				  &PyTuple_Type, &yargs,
				  &length);
	if (!result)
		return NULL;

	if (yield && !PyCallable_Check(yield)) {
		PyErr_Format(PyExc_TypeError,
			     "'%s' object not callable",
			     yield->ob_type->tp_name);
		return NULL;
	}

	buffer.len  = PyString_GET_SIZE(input);
	buffer.off  = 0;
	buffer.buf  = PyString_AS_STRING(input);
	buffer.func = yield;
	buffer.size = length;
	buffer.last = 0;
	buffer.args = yargs;

	output = _deserialize(&buffer, 0);
	if (!output)
		_deserialize_error(&buffer);

	return output;
}

static PyObject *utf8_enable(PyObject *self, PyObject *noargs)
{
	utf8_support = 1;
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *utf8_disable(PyObject *self, PyObject *noargs)
{
	utf8_support = 0;
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *utf8_enabled(PyObject *self, PyObject *noargs)
{
	return PyBool_FromLong((long)utf8_support);
}

static PyObject *wls_enable(PyObject *self, PyObject *noargs)
{
	wls_on = 1;
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *wls_disable(PyObject *self, PyObject *noargs)
{
	wls_on = 0;
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *wls_enabled(PyObject *self, PyObject *noargs)
{
	return PyBool_FromLong((long)wls_on);
}
static PyObject *echo_maxint(PyObject *self, PyObject *noargs)
{
	return PyInt_FromLong(LONG_MAX);
}

static PyObject *echo_minint(PyObject *self, PyObject *noargs)
{
	return PyInt_FromLong(LONG_MIN);
}

static PyMethodDef _bin_methods[] = {
	{"serialize", py_serialize, METH_VARARGS,
	 PyDoc_STR("serialize(object[, callback[, args[, frequency]]]) -> "
		   "string.\n\nGiven  a python object  encode it  into a  "
		   "python string.  An optional\ncallback(offset[,args])  "
		   "will be  periodically called  with  number of\nbytes so"
		   "far encoded as  the first parameter. The  remaining "
		   "optional\nparameters to the callback are  supplied as "
		   "an optional args parameter\nto  the serialize  function."
		   " Finally  an optional  frequency parameter\ndetermines "
		   "approximately how many  bytes are encoded between each "
		   "call\nto the callback function. (default 8K)\n")},
	{"deserialize", py_deserialize, METH_VARARGS,
	 PyDoc_STR("deserialize(object[, callback[, args[, frequency]]]) -> "
		   "string.\n\nGiven  a python string  decode it  into a  "
		   "python object.  An optional\ncallback(offset[,args])  "
		   "will be  periodically called  with  number of\nbytes so"
		   "far encoded as  the first parameter. The  remaining "
		   "optional\nparameters to the callback are  supplied as "
		   "an optional args parameter\nto  the serialize  function."
		   " Finally  an optional  frequency parameter\ndetermines "
		   "approximately how many  bytes are encoded between each "
		   "call\nto the callback function. (default 8K)\n")},
	{"utf8_enable",  utf8_enable,  METH_NOARGS,
	 "utf8_enable() -> None\n\nEnable UTF8 encoding support\n"},
	{"utf8_disable", utf8_disable, METH_NOARGS,
	 "utf8_disable() -> None\n\nDisable UTF8 encoding support\n"},
	{"utf8_enabled", utf8_enabled, METH_NOARGS,
	 "utf8_enabled() -> status\n\nReturns True if UTF8 encoding is enable\n"},
	{"wls_on",  wls_enable,  METH_NOARGS,
	 "wls_on() -> None\n\nEnable encodable object whitelist (default)\n"},
	{"wls_off", wls_disable, METH_NOARGS,
	 "wls_off() -> None\n\nDisable encodable object whitelist (attempt to encode all objects)\n"},
	{"wls_status", wls_enabled, METH_NOARGS,
	 "wls_status() -> status\n\nReturns encodable object whitelist status\n"},
	{"min_int", echo_minint, METH_NOARGS,
	 "min_int() -> int\n\nReturns smallest integer that can be encoded\n"},
	{"max_int", echo_maxint, METH_NOARGS,
	 "max_int() -> int\n\nReturns largest integer that can be encoded\n"},
	{NULL, NULL, 0, NULL}
};


#define INIT_STR(s, n)  if (!(s = PyString_InternFromString(n))) return;

PyMODINIT_FUNC initwbin(void)
{
	struct whitelist_entry *entry;
	PyObject *name;

	(void)Py_InitModule3("wbin", _bin_methods, wbin_module_documentation);
	/*
	 * empty tuple for default arguments to yield function
	 */
	empty_tuple = PyTuple_New(0);
	if (!empty_tuple)
		return;
	/* 
	 * attempt an import of cPickle which, if available, can be used
	 * as a fallback for complex objects. error is not checked here,
	 * the failure will occur when a compex object is encountered.
	 */
	INIT_STR(cpickle_str, "cPickle");
	INIT_STR(cploads_str, "loads");
	INIT_STR(cpdumps_str, "dumps");

	cpick = PyImport_Import(cpickle_str);
	/*
	 * import classes for cpickle white list.
	 */
	for (entry = whitelist; entry->mname; entry++) {
		name = PyString_InternFromString(entry->mname);
		if (!name)
			return;

		entry->mod = PyImport_Import(name);
		if (!entry->mod)
			return;

		name = PyString_InternFromString(entry->cname);
		if (!name)
			return;

		entry->cls = PyObject_GetAttr(entry->mod, name);
		if (!entry->cls)
			return;
	}
}

/*
 * Local Variables:
 * c-file-style: "linux"
 * indent-tabs-mode: t
 * End:
 */
