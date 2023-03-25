import cv2
from mtcnn import MTCNN
import json
import Cords
from PIL import Image
from numpy import asarray
import numpy as np
import io

class Face:
	def __init__(self,confidence,cords,frame):
		self.confidence = confidence
		self.cords= cords
		self.frame= frame

	def print_info(self):
		print(self.confidence,self.label,self.json_path,self.face_num)


	def crop_and_resize(self):
		# crop
		crop_img = self.frame[self.cords.get_y()-5:self.cords.get_y()+self.cords.get_height()+15, self.cords.get_x()-5:self.cords.get_x()+self.cords.get_width()+15]
		# resize
		res = cv2.resize(crop_img, dsize=(224, 224), interpolation=cv2.INTER_CUBIC)
		return res

	
	def get_dimensions(self):
		return self.cords.get_width(), self.cords.get_height(), self.frame.shape[2]

	def extract_face(self):
		face_array = self.get_face_array()
		x, y, w, h = self.cords.get_x(),self.cords.get_y(),self.cords.get_width(),self.cords.get_height()
		crop_img = self.crop_and_resize()
		print(face_array)
		if crop_img.size == 0:
			print("no picture")
			return None
		else:
			# resize the image
			required_size = (224, 224)
			resized_image = cv2.resize(crop_img, required_size)
			return resized_image

		
	def get_face_array(self):
		x, y, w, h = self.cords.get_x(),self.cords.get_y(),self.cords.get_width(),self.cords.get_height()
		return self.frame[y:y+h, x:x+w]			

		
		

