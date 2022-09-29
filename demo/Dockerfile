# start by pulling the python image
FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine
RUN apk add --no-cache bash
RUN apk add py3-pip
RUN apk add build-base
RUN apk add python3-dev
RUN apk add --update nodejs npm
RUN apk add jq

ARG PROD
ENV PROD=${PROD:-true}

RUN wget https://releases.hashicorp.com/terraform/1.2.9/terraform_1.2.9_linux_amd64.zip
RUN unzip terraform_1.2.9_linux_amd64.zip
RUN mv terraform /usr/bin/terraform

# Frontend
WORKDIR /app/frontend

COPY frontend/ /app/frontend/
RUN npm install react-scripts
RUN npm run build

# Backend
WORKDIR /app

COPY principal.env /app/principal.env

COPY ./requirements.txt /app/requirements.txt
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY create_keys.py /app/create_keys.py
RUN python3 create_keys.py

COPY app.py /app/app.py

RUN mkdir -p /app/deploy/.terraform.d/plugin-cache
COPY deploy/.terraformrc /root
COPY deploy/terraform /app/deploy/terraform
COPY deploy/webhook-src /app/deploy/webhook-src/

EXPOSE 8080
CMD exec gunicorn --bind=0.0.0.0:8080 --workers=1 --threads=8 --log-level=info app:app
