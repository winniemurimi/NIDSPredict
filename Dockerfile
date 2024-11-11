FROM python:3.8

WORKDIR /code

COPY  ./requirements.txt /code/requirements.txt


RUN pip3 install --no-cache-dir -r /code/requirements.txt

COPY  .  /code/Predict

EXPOSE 8000

CMD ["uvicorn", "Predict.KNNDeploy:app", "--host", "0.0.0.0", "--port", "8000"]