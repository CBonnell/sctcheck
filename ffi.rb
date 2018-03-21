# Copyright (c) 2018 Corey Bonnell
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

require 'ffi'

module SctCheck
    module OpensslCT
        extend FFI::Library

        BIO_CTRL_INFO = 3

        SCT_SOURCE_X509V3_EXTENSION = 2

        ffi_lib 'ssl'

        attach_function :CTLOG_STORE_new, [], :pointer
        attach_function :CTLOG_STORE_load_file, [:pointer, :string], :int
        attach_function :CTLOG_STORE_free, [:pointer], :void

        attach_function :OPENSSL_sk_num, [:pointer], :int
        attach_function :OPENSSL_sk_value, [:pointer, :int], :pointer

        attach_function :BIO_new, [:pointer], :pointer
        attach_function :BIO_ctrl, [:pointer, :int, :long, :pointer], :long
        attach_function :BIO_s_mem, [], :pointer
        attach_function :BIO_free, [:pointer], :int

        attach_function :d2i_X509, [:pointer, :pointer, :int], :pointer
        attach_function :X509_free, [:pointer], :void

        attach_function :d2i_SCT_LIST, [:pointer, :pointer, :int], :pointer
        attach_function :SCT_LIST_free, [:pointer], :void
        attach_function :SCT_print, [:pointer, :pointer, :int, :pointer], :void
        attach_function :SCT_get0_log_id, [:pointer, :pointer], :size_t
        attach_function :SCT_set_source, [:pointer, :int], :int
        attach_function :SCT_validate, [:pointer, :pointer], :int
        attach_function :SCT_validation_status_string, [:pointer], :string

        attach_function :CT_POLICY_EVAL_CTX_new, [], :pointer
        attach_function :CT_POLICY_EVAL_CTX_free, [:pointer], :void
        attach_function :CT_POLICY_EVAL_CTX_set1_cert, [:pointer, :pointer], :int
        attach_function :CT_POLICY_EVAL_CTX_set1_issuer, [:pointer, :pointer], :int
        attach_function :CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE, [:pointer, :pointer], :void

        attach_function :ERR_load_CT_strings, [], :int
        attach_function :ERR_get_error, [], :ulong
        attach_function :ERR_error_string_n, [:ulong, :pointer, :size_t], :void
    end

    module LibC
        extend FFI::Library
        ffi_lib FFI::Library::LIBC

        attach_function :memcpy, [:pointer, :pointer, :size_t], :pointer
    end
end
