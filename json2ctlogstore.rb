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

require 'json'

ID_REGEX = /^(?<id>[^.]+)\./

def get_id log
    m = ID_REGEX.match log[:dns_api_endpoint]

    m.nil? ? nil : m['id']
end

def read_logs logs
    logs.map do |log|
        {
            :description => log[:description],
            :key => log[:key],
            :id => get_id(log)
        }
    end
end

in_path = ARGV[0]

content = File.read in_path

json = JSON.parse content, :symbolize_names => true
logs = read_logs json[:logs]

out_path = File.join(File.dirname(in_path), File.basename(in_path, '.*') + '.ini')

File.open(out_path, 'w') do |f|
    f.puts('enabled_logs = ' + logs.map {|l| l[:id]}.join(','))

    logs.each do |log|
        f.puts "[#{log[:id]}]"
        f.puts "description = #{log[:description]}"
        f.puts "key = #{log[:key]}"
        f.puts
    end
end
