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

require 'openssl'
require 'ffi'

require_relative './ffi'

SctCheck::OpensslCT.ERR_load_CT_strings

module SctCheck
    class Checker
        def initialize ctlog_store_file, logger
            @ctlog_store_file = ctlog_store_file
            @logger = logger
        end

        def check cert, issuer
            ext = cert.extensions.find {|e| e.oid == 'ct_precert_scts'}

            if ext.nil?
                @logger.error "No SCT List extension found in certificate"
                return true
            end

            is_interesting = false

            ext_asn1 = OpenSSL::ASN1.decode ext.to_der
            ext_value_asn1 = OpenSSL::ASN1.decode(ext_asn1.to_a.last).value

            scts = read_sct_stack ext_value_asn1
            cert_x509 = create_x509 cert
            issuer_x509 = create_x509 issuer
            ctstore = load_ctstore
            eval_ctx = create_context ctstore, cert_x509, issuer_x509

            count = OpensslCT.OPENSSL_sk_num scts
            @logger.info "There are #{count} embedded SCTs"

            # having a SCTList with no embedded SCTs is rather peculiar
            is_interesting = true if count == 0

            count.times do |i|
                sct = OpensslCT.OPENSSL_sk_value scts, i
                OpensslCT.SCT_set_source sct, OpensslCT::SCT_SOURCE_X509V3_EXTENSION

                bio = FFI::AutoPointer.new \
                    OpensslCT.BIO_new(OpensslCT.BIO_s_mem),
                    OpensslCT.method(:BIO_free)

                OpensslCT.SCT_print sct, bio, 0, ctstore
                sct_print = read_bio_string bio

                ret = OpensslCT.SCT_validate sct, eval_ctx
                validation_status = OpensslCT.SCT_validation_status_string sct

                if ret < 1
                    err = get_last_error_string
                    validation_status += " (#{err[err.rindex(':') + 1..-1]})"
                    level = Logger::ERROR

                    is_interesting = true
                else
                    level = Logger::INFO
                end

                @logger.add level, "#{sct_print}\n    Status    : #{validation_status}"
            end

            is_interesting
        end

        private

        def load_ctstore
            ctstore = FFI::AutoPointer.new \
                OpensslCT.CTLOG_STORE_new, OpensslCT.method(:CTLOG_STORE_free)
            raise "Could not allocate CTLOG_STORE" if ctstore.null?

            ret = OpensslCT.CTLOG_STORE_load_file ctstore, @ctlog_store_file
            raise "Could not load CTLOG_STORE file \"#{@ctlog_store_file}\": #{get_last_error_string}" if ret != 1

            ctstore
        end

        def create_x509 cert
            der = cert.to_der

            x509 = nil
            FFI::MemoryPointer.new(:uchar, der.length) do |der_buf|
                der_buf.write_string der

                FFI::MemoryPointer.new(:pointer, 1) do |buf_ptr|
                    buf_ptr.write_pointer der_buf.address

                    x509 = FFI::AutoPointer.new \
                        OpensslCT.d2i_X509(nil, buf_ptr, der.length),
                        OpensslCT.method(:X509_free)
                    raise "Could not read X.509 certificate DER: #{get_last_error_string}" if x509.null?
                end
            end

            x509
        end

        def create_context ctstore, ee_cert, issuer_cert
            ctx = FFI::AutoPointer.new \
                OpensslCT.CT_POLICY_EVAL_CTX_new, OpensslCT.method(:CT_POLICY_EVAL_CTX_free)
            raise "Could not allocate CT_POLICY_EVAL_CTX" if ctx.null?

            ret = OpensslCT.CT_POLICY_EVAL_CTX_set1_cert ctx, ee_cert
            raise "Error setting end-entity certificate in CT_POLICY_EVAL_CTX: #{get_last_error_string}" if ret != 1

            ret = OpensslCT.CT_POLICY_EVAL_CTX_set1_issuer ctx, issuer_cert
            raise "Error setting issuer certificate in CT_POLICY_EVAL_CTX: #{get_last_error_string}" if ret != 1

            OpensslCT.CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE ctx, ctstore

            ctx
        end

        def read_sct_stack data
            scts = nil

            FFI::MemoryPointer.new(:uchar, data.length) do |der_buf|
                der_buf.write_string data

                FFI::MemoryPointer.new(:pointer, 1) do |buf_ptr|
                    buf_ptr.write_pointer der_buf.address

                    scts = FFI::AutoPointer.new \
                        OpensslCT.d2i_SCT_LIST(nil, buf_ptr, data.length),
                        OpensslCT.method(:SCT_LIST_free)
                    raise "Could not read SCTS: #{get_last_error_string}" if scts.null?
                end
            end

            scts
        end

        def read_bio_string bio
            str = nil

            FFI::MemoryPointer.new(:pointer, 1) do |bio_data_ptr|
                length = OpensslCT.BIO_ctrl bio, OpensslCT::BIO_CTRL_INFO, 0, bio_data_ptr

                FFI::MemoryPointer.new(:uchar, length) do |bio_data_buf|
                    LibC.memcpy bio_data_buf, bio_data_ptr.read_pointer, length

                    str = bio_data_buf.read_string_length length
                end
            end

            str
        end

        def get_last_error_string
            str = nil

            err = OpensslCT.ERR_get_error
            FFI::MemoryPointer.new(:uchar, 1024) do |buf|
                OpensslCT.ERR_error_string_n err, buf, buf.total

                str = buf.read_string_to_null
            end

            str
        end
    end
end
