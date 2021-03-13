/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2014 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 */

/*
 * argusWgan - add descriptor labels to flows.
 *           this particular labeler adds descriptors based
 *           on addresses.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 * $Id: //depot/gargoyle/clients/examples/argusWgan/argusWgan.c#17 $
 * $DateTime: 2016/11/30 00:54:11 $
 * $Change: 3245 $
 */

#ifdef HAVE_PYTHON_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>

#if defined(ARGUS_SOLARIS)
#include <strings.h>
#include <string.h>
#endif

#include <math.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_label.h>
#include <argus_client.h>
#include <argus_filter.h>
#include <argus_main.h>
#include <argus_cluster.h>

static int argus_version = ARGUS_VERSION;
static PyObject *ArgusPyError;
static PyObject *argusWgan_critic(PyObject *, PyObject *);
PyMODINIT_FUNC PyInit_argusWgan(void);

static PyMethodDef ArgusMethods[] = {
    {"critic",  argusWgan_critic, METH_VARARGS, "Score an argus flow."},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef argusWgan = {
    PyModuleDef_HEAD_INIT,
    "argusWgan",   /* name of module */
    NULL,      /* module documentation, may be NULL */
    -1,        /* size of per-interpreter state of the module,
                  or -1 if the module keeps state in global variables. */
    ArgusMethods
};

PyMODINIT_FUNC
PyInit_argusWgan()
{
   PyObject *m;

   m = PyModule_Create(&argusWgan);
   if (m == NULL)
      return NULL;

   ArgusPyError = PyErr_NewException("argusWgan.error", NULL, NULL);
   Py_XINCREF(ArgusPyError);
   if (PyModule_AddObject(m, "error", ArgusPyError) < 0) {
        Py_XDECREF(ArgusPyError);
        Py_CLEAR(ArgusPyError);
        Py_DECREF(m);
        return NULL;
   }

   return m;
}


static PyObject *
argusWgan_critic(PyObject *self, PyObject *args)
{
    int sts;

    if (!PyArg_ParseTuple(args, "s", &command))
        return NULL;
    sts = system(command);
    if (sts < 0) {
        PyErr_SetString(ArgusPyError, "System command failed");
        return NULL;
    }
    return PyLong_FromLong(sts);
}


#endif  // HAVE_PYTHON_H
