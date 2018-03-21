FROM ruby

RUN gem install ffi

WORKDIR /usr/src/app

COPY *.rb ./
COPY chrome/ chrome/

RUN ruby json2ctlogstore.rb chrome/*.json
RUN ruby write_intermediates.rb /issuers

VOLUME "/certs"
VOLUME "/issuers"

CMD ["ruby", "main.rb"]
