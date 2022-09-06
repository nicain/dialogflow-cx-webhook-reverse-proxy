# start by pulling the python image
FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine
RUN apk add --no-cache bash
RUN apk add py3-pip
RUN apk add build-base
RUN apk add python3-dev

# copy the requirements file into the image
COPY ./requirements.txt /app/requirements.txt

# switch working directory
WORKDIR /app

# install the dependencies and packages in the requirements file
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

EXPOSE 8080

# copy every content from the local file to the image
COPY app.py /app/app.py
COPY create_keys.py /app/create_keys.py
COPY frontend/build/ /app/frontend/build/

RUN python3 create_keys.py

ARG PROD
ENV PROD=${PROD:-true}

CMD exec gunicorn --bind=0.0.0.0:8080 --workers=1 --threads=8 --log-level=info app:app
