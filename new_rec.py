
# face verification with the VGGFace2 model
from matplotlib import pyplot
from PIL import Image
from numpy import asarray
from scipy.spatial.distance import cosine
from mtcnn.mtcnn import MTCNN
from keras_vggface.vggface import VGGFace
from keras_vggface.utils import preprocess_input
import numpy as np
 
# extract a single face from a given photograph
def extract_face(filename, required_size=(224, 224)):
    # load image from file
    pixels = pyplot.imread(filename)
    # create the detector, using default weights
    detector = MTCNN()
    # detect faces in the image
    results = detector.detect_faces(pixels)
    # extract the bounding box from the first face
    x1, y1, width, height = results[0]['box']
    x2, y2 = x1 + width, y1 + height
    # extract the face
    face = pixels[y1:y2, x1:x2]
    # resize pixels to the model size
    image = Image.fromarray(face)
    image = image.resize(required_size)
    face_array = asarray(image)
    return face_array
 
# extract faces and calculate face embeddings for a list of photo files
def get_embeddings(faces):
    samples = np.asarray(faces, 'float32')
    # Add extra dimension for the batch
    samples = np.expand_dims(samples, axis=0)
    # prepare the face for the model, e.g. center pixels
    samples = preprocess_input(samples, version=2)
    # create a vggface model
    model = VGGFace(model='resnet50', include_top=False, input_shape=(224, 224, 3), pooling='avg')
    # perform prediction
    yhat = model.predict(samples)
    print("yhat={}".format(yhat))
    print("yhat.shape: {}; len(yhat.shape): {}".format(yhat.shape, len(yhat.shape)))
    return yhat
    
    




 
# determine if a candidate face is a match for a known face
def is_match(known_embedding, candidate_embedding, thresh=0.6):
    # calculate distance between embeddings
    print(candidate_embedding)
    score = cosine(known_embedding[0], candidate_embedding[0])
    if score <= thresh:
        print('>face is a Match (%.3f <= %.3f)' % (score, thresh))
        return 1
    else:
        print('>face is NOT a Match (%.3f > %.3f)' % (score, thresh))
        return 0
 


# verify known photos of sharon
