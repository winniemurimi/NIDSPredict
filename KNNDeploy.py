from fastapi import FastAPI, File, UploadFile 
from pydantic import BaseModel
import numpy 
import pandas as pd  # Ensure you import pandas
import pickle
import os

# Load the trained model
model_path = os.path.join(os.path.dirname(__file__), 'models', 'knn_multi.pkl')
with open(model_path, 'rb') as file:
    knn = pickle.load(file)

# Initialize FastAPI app
app = FastAPI()

# Define the input data model
class InputData(BaseModel):
    count: float
    logged_in: float
    srv_serror_rate: float
    serror_rate: float
    dst_host_serror_rate: float
    dst_host_same_srv_rate: float
    dst_host_srv_serror_rate: float
    dst_host_srv_count: float
    same_srv_rate: float

@app.get('/')
def index():
    return {'message': 'Network Introsion Detection'}

@app.post("/predict/csv/")
async def predict_csv(file: UploadFile = File(...)):
    # Read the CSV file
    df = pd.read_csv(file.file)

    # Ensure the correct columns are present
    #required_columns = [
        #'count', 'logged_in', 'srv_serror_rate', 'serror_rate',
        #'dst_host_serror_rate', 'dst_host_same_srv_rate',
        #'dst_host_srv_serror_rate', 'dst_host_srv_count', 'same_srv_rate'
    #]
    
    #if not all(col in df.columns for col in required_columns):
        #return {"error": "CSV must contain the following columns: " + ", ".join(required_columns)}

    # Prepare the input array for predictions
    input_array = df.values

    # Make predictions
    predictions = knn.predict(input_array)

    # Map predictions to labels
    labels = ["DOS", "Probe", "R2L", "U2R", "Normal"]
    classified_labels = [labels[pred] for pred in predictions]

    return {"classifications": classified_labels}