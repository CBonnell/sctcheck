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

require 'csv'
require 'openssl'
require 'digest'
require 'base64'
require 'fileutils'
require 'open-uri'

$out_dir = ARGV[0]

$in = open(ARGV.length > 1 ?
    ARGV[1] :
    'https://ccadb-public.secure.force.com/mozilla/PublicAllIntermediateCertsWithPEMCSV')

FileUtils.mkdir_p $out_dir unless Dir.exist? $out_dir

CSV.foreach($in, :encoding => 'UTF-8').with_index do |row, lineno|
    # skip first line with column headers
    next if lineno == 0

    STDOUT.puts "Processing line #{lineno + 1}..."
    pem = row.last
        .gsub('\'', '')
        .gsub('-----BEGIN CERTIFICATE-----', '')
        .gsub('-----END CERTIFICATE-----', '')
        .gsub("\r", '')
        .gsub("\n", '')
    der = Base64.decode64 pem
    cert = OpenSSL::X509::Certificate.new der

    cert_fingerprint = Digest::SHA2.hexdigest cert.to_der

    dest_file = File.join $out_dir, "#{cert_fingerprint}.der"
    puts "Issuer \"#{cert.subject.to_s}\" with fingerprint #{cert_fingerprint} " +
        "appears to already have been written, skipping..." if File.exist? dest_file

    File.write dest_file, der
end
