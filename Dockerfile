FROM python:2.7
EXPOSE 5000
RUN pip install Flask
RUN pip install Flask-JWT
RUN pip install Flask-OAuth
RUN mkdir /code
COPY  ./code/* /code/
WORKDIR /code
ENV FLASK_APP basic.py
CMD ["/usr/local/bin/flask", "run", "--host=0.0.0.0"]
