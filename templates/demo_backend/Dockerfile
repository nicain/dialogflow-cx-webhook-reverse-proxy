# start by pulling the python image
FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine
RUN apk add --no-cache bash
RUN apk add py3-pip

# copy the requirements file into the image
COPY ./requirements.txt /app/requirements.txt

# switch working directory
WORKDIR /app

# install the dependencies and packages in the requirements file
RUN pip install -r requirements.txt

EXPOSE 5000

# copy every content from the local file to the image
COPY ./app.py /app/app.py
COPY ./tasks.py /app/tasks.py
COPY ./config.json /app/config.json
COPY ./demo-backend /app/keys/demo-backend

CMD exec gunicorn --bind=0.0.0.0:5000 --workers=1 --threads=8 --log-level=info app:app