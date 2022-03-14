FROM python:3.9-bullseye

WORKDIR /mudscope

COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt
COPY . .

CMD ["tail", "-f", "/dev/null"]