FROM python:3.7
WORKDIR /mn-backend
ADD . /mn-backend
RUN pip install -r requirements.txt
EXPOSE 5183
# CMD python main.py