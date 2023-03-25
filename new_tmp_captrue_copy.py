from pathlib import Path
from tkinter.messagebox import NO
import cv2
import numpy as np
from facenet_pytorch import MTCNN # pip install facenet-pytorch
from tqdm import tqdm
import torch
from Cords import Cords
from whitelist import insertVaribleIntoTable,main,get_index,add_admin
from face import Face
from new_rec import get_embeddings
import datetime
import time
import os
import hashlib
class FastMTCNN(object):
    """Fast MTCNN implementation."""
    
    def __init__(self, stride, resize=1, *args, **kwargs):
        """Constructor for FastMTCNN class.
        
        Arguments:
            stride (int): The detection stride. Faces will be detected every `stride` frames
                and remembered for `stride-1` frames.
        
        Keyword arguments:
            resize (float): Fractional frame scaling. [default: {1}]
            *args: Arguments to pass to the MTCNN constructor. See help(MTCNN).
            **kwargs: Keyword arguments to pass to the MTCNN constructor. See help(MTCNN).
        """
        self.stride = stride
        self.resize = resize
        self.mtcnn = MTCNN(*args, **kwargs)
        
    def __call__(self, frames):
        """Detect faces in frames using strided MTCNN."""
        if self.resize != 1:
            frames = [
                cv2.resize(f, (int(f.shape[1] * self.resize), int(f.shape[0] * self.resize)))
                    for f in frames
            ]
                      
        boxes, probs = self.mtcnn.detect(frames[::self.stride])

        return (boxes, probs)


class Capture():
    def __init__(self,name,email):
        self.email=email
        self.name=name
        #intialize data base
        main()


    def second_passed(self,oldtime):
        if oldtime==None:
            return True
        return time.time() - oldtime >= 0.05

    def add_embedings(self,embedings,name,email,is_admin,rescaled_frame):
        insertVaribleIntoTable(name, is_admin, email,embedings,rescaled_frame)

    def capturing(self):
        confidence_th = 0.98
        is_admin=0





        device = 'cuda' if torch.cuda.is_available() else 'cpu'

        FONT = cv2.FONT_HERSHEY_SIMPLEX
        save_output_movie = False
        input_folder = r'C:/Users/User/Documents/cyber/project/detection/data/positive/' 
        input_folder2 = r'C:/Users/User/Documents/cyber/project/detection/data/anchor/' 
        current_path=''
        output_folder = r'C:/Users/User/Documents/cyber/project/detection/data/labels2/'
        movie_file_name = 'fast_mtcnn_face_detector'


        cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        if(cap is None):
            print('Camera resource is not available')
            exit(-1)
        width  = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = 24
        oldtime= None
        highest_conf= 0
        current_conf=0
        bestPic = None
        fourcc = cv2.VideoWriter_fourcc(*'DIVX')
        output_file_url = output_folder + '/' + movie_file_name + '.mp4'
        if(save_output_movie == True):
            out = cv2.VideoWriter(output_file_url, fourcc, fps, (width,height))

        fast_mtcnn = FastMTCNN(
        stride=4,
        resize=0.5,
        margin=14,
        factor=0.6,
        keep_all=True,
        device=device
        )
        if (is_admin):
            password = input("enter password")
            password = password.encode()
            password= hashlib.sha256(password).hexdigest()
            add_admin(self.name,password)

        running_idx = 0
        while(True):
            ret, frame = cap.read(0)
            if(ret == False):
                print('Frame was not fetched')
                exit(-1)
            else:
                print("Filming!")
                running_idx = running_idx + 1
            frames_rgb = []
            # add frame iteration
            cv2.rectangle(frame, (0, 0), (100, 20), (0, 0, 0), -1)
            frame_title = 'F:{0}'.format(running_idx)
            cv2.putText(frame, frame_title, (5, 17), FONT, 0.4, (255, 255, 255), 1, cv2.LINE_AA)
            # detect faces in the image
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            frames_rgb.append(frame_rgb)
            faces_rois, faces_confs = fast_mtcnn(frames_rgb)
            begin_time = time.time()

            for roi, conf in zip(faces_rois, faces_confs):
                
                if(roi is None or conf is None):
                    continue
                conf = float(conf[0])
                roi = roi[0]
                x, y, width, height = int(roi[0] + roi[2]/2) , int(roi[1] + roi[3]/2), int(roi[2]), int(roi[3])
                if (self.second_passed(oldtime)):
                    oldtime=time.time()
                   
                    cords = Cords(x,y,width,height)
                    face =Face(conf,cords,frame)
                    if(conf >= confidence_th):
                        current_conf=conf
                        bestPic=face
                    embedings=""
            cv2.imshow('frame', frame)
            if (time.time() - begin_time >=30) or (current_conf>=0.999) or (cv2.waitKey(1) & 0xFF == ord('q')):
                break
        rescaled_frame = face.extract_face()
        embedings= get_embeddings(rescaled_frame)
        self.add_embedings(embedings,self.name,self.email,is_admin,rescaled_frame)
        print('Finished processing. Release resources.')
        cap.release()
        cv2.destroyAllWindows()


