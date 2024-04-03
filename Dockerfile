FROM ubuntu:22.04

ADD . /src
WORKDIR /src

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y && apt-get upgrade -y
RUN apt-get install -y python3-pip

RUN pip3 install -r requirements.txt

# UDP
EXPOSE 1812/UDP

CMD ["python3", "foxpass-radius-agent.py", "-c", "foxpass-radius-agent.conf"]
