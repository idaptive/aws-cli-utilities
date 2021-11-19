FROM git.loc.gov:4567/devops/docker-hub-mirror/python:latest

RUN apt-get update -qqy && apt-get upgrade -qqy && apt-get install -y less groff-base && apt-get autoremove -qqy && apt-get autoclean -qqy

RUN mkdir /tmp/awscli-install && cd /tmp/awscli-install && curl -LO --fail --silent "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" && unzip -q awscli-exe-linux-x86_64.zip && ./aws/install && rm -rf /tmp/awscli-install

RUN curl --fail --silent -Lo "/tmp/session-manager-plugin.deb" "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_$(test "$(dpkg --print-architecture)" = "arm64"  && echo "arm64" || echo "64bit" )/session-manager-plugin.deb" && dpkg -i /tmp/session-manager-plugin.deb && rm /tmp/session-manager-plugin.deb

ADD ["AWS CLI - Idaptive V1", "/tmp/python-cli"]
RUN cd /tmp/python-cli && python setup.py install && rm -rf /tmp/python-cli

ADD docker-entrypoint /usr/local/bin/docker-entrypoint

RUN adduser --system aws-user
USER aws-user
WORKDIR /home/aws-user

ENV AWS_DEFAULT_REGION=us-east-1
ENV IDAPTIVE_TENANT=loc.my.idaptive.app
ENV IDAPTIVE_USE_APP_NAME_FOR_PROFILE=true

ENTRYPOINT ["docker-entrypoint"]
