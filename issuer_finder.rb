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
require 'digest'

module SctCheck
    class StaticIssuerFinder
        def initialize issuer_path
            @cert = OpenSSL::X509::Certificate.new File.read(issuer_path)            
        end

        def find
            @cert
        end
    end

    class DirectoryIssuerFinder
        def initialize issuers_dir, logger
            @logger = logger

            
            @issuers = Dir.chdir issuers_dir do |d|
                Dir.glob("**/*").map do |f|
                    path = File.join issuers_dir, f

                    OpenSSL::X509::Certificate.new File.read(path)
                end
            end
        end

        # TODO: this should probably be improved
        def find cert
            matching_issuers_by_dn = @issuers.select {|i| i.subject.to_der == cert.issuer.to_der}
            
            @logger.debug "#{matching_issuers_by_dn.length} issuer(s) match by DN"
            matching_issuers_by_dn.each {|i| @logger.debug "#{i.subject.to_s}"}

            matching_issuers_by_dn.find do |issuer|
                begin
                    cert.verify issuer.public_key
                rescue OpenSSL::X509::CertificateError
                    false
                end
            end
        end
    end
end
