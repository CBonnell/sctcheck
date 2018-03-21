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
require 'logger'
require 'digest'

require_relative 'checker'
require_relative 'issuer_finder'
require_relative 'utils'

$cert = ENV['CERT'] || '/certs'
$issuer = ENV['ISSUER'] || '/issuers'
$level = ENV['LOG_LEVEL'] || Logger::INFO
$known_logs = ENV['KNOWN_LOGS'] || Dir.glob('chrome/*.ini').first

$logger = Logger.new STDOUT
$logger.level = $level
$logger.formatter = Proc.new {|s, d, p, m| "#{s.ljust 8, ' '}: #{m}\n"}

$logger.debug "Certificate(s): #{$cert}"
$logger.debug "Issuer(s)     : #{$issuer}"
$logger.debug "Log level     : #{$level}"
$logger.debug "Known logs    : #{$known_logs}"

raise "The specified known logs file doesn't exist" unless File.file? $known_logs
raise "The specified certificate(s) file/directory does not exist" unless File.exist? $cert
raise "The specified issuer(s) file/directory does not exist" unless File.exist? $issuer

if File.directory? $cert
    Dir.chdir $cert do |d|
        $certs_to_check = Dir.glob("**/*").map {|f| File.join $cert, f}
    end
else
    $certs_to_check = [$cert]
end

$finder = File.directory?($issuer) ?
    SctCheck::DirectoryIssuerFinder.new($issuer, $logger) :
    SctCheck::StaticIssuerFinder.new($issuer)
$checker = SctCheck::Checker.new $known_logs, $logger

$certs_to_check.each do |c|
    $logger.info "Checking certificate \"#{c}\"..."

    cert = OpenSSL::X509::Certificate.new File.read(c)

    SctCheck::Utils::log_cert_info 'Read certificate', Logger::INFO, cert

    issuer_cert = $finder.find cert

    if issuer_cert.nil?
        $logger.error "Could not find issuer for certificate \"#{c}\""
        next
    end

    SctCheck::Utils::log_cert_info 'Found issuer', Logger::DEBUG, issuer_cert

    $checker.check cert, issuer_cert
end
