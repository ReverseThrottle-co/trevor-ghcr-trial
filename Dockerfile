FROM demisto/python3:3.12.13.10404775@sha256:f92834aedf2266fcb2c11476a9e537fdd31c60f65f3260deae3061d7ab5a192e
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
WORKDIR /app
COPY . /app/
COPY bot_gateway.py gateway_runtime.py /usr/local/lib/python3.12/site-packages/
