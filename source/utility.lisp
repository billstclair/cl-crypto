(in-package :cl-crypto)

;; Just a quick-n-dirty declared pairwise
;; multiplication, addition, subtraction, and logxor
;; macro - probably a weak version of the GBBOpen
;; one in declared numerics, haven't looked at that yet...
;; Have not bothered to typecase these as I expect
;; we will just use GBBOpen's stuff

(defmacro %internal-declared-op (fn &rest args)
  (labels ((rec (args)
	     (if (and (consp args) (null (cdr args)))
		 `(the fixnum ,@args)
		 `(the fixnum
		    (,fn (the fixnum ,(car args))
			 ,(rec (cdr args)))))))
    (rec args)))

(defmacro @+ (&rest args)
  `(%internal-declared-op + ,@args))

(defmacro @- (&rest args)
  `(%internal-declared-op - ,@args))

(defmacro @* (&rest args)
  `(%internal-declared-op * ,@args))

(defmacro @logxor (&rest args)
  `(%internal-declared-op logxor ,@args))


;; Similar for ash and aref
(defmacro @ash (x n)
  `(the fixnum (ash (the fixnum ,x) ,n)))

(defmacro @aref (type table n)
  `(aref (the (simple-array ,type) ,table) ,n))


;; Always need these
(defmacro with-gensyms ((&rest names) &body body)
  `(let ,(loop for n in names collect `(,n (gensym)))
     ,@body))

(defmacro for ((var start stop &key (step 1)) &body body)
  "Simplified do loop with single iteration variable
   and ability to set both starting value and step size"
  (let ((gstop (gensym)))
    `(do ((,var ,start (+ ,var ,step))
	  (,gstop ,stop))
	 ((> ,var ,gstop))
       ,@body)))

(defmacro define-constant (name value &optional doc)
  "Works as defconstant. Made to avoid trouble with sbcl's strict
   interpretation of the ansi standard."
  (let ((old-value (gensym)))
    `(defconstant ,name 
       (if (boundp ',name) 
	   (let ((,old-value (symbol-value ',name)))
	     (if (equalp ,old-value ,value)
		 ,old-value
		 ,value))
	   ,value)
       ,@(when doc (list doc)))))

;; Useful for crypto manipulations
(defmacro rot-byte-R ()
  "Byte rotation to the right"
  ;; This is a macro since it is called when making constants
  (let ((word (gensym)))
    `(lambda (,word) 
      (logxor (ash (ldb (byte 8 0) ,word) 24)
       (ash ,word -8)))))

(defun rot-uint-32-L (word &optional (n 8))
  "32-bit rotation to the left by n bits"
  (logxor (ldb (byte n (- 32 n)) word)
	  (ash (ldb (byte (- 32 n) 0) word) n)))
   
(defun string->char-array (str)
  (make-array (length str)
	      :initial-contents
	      str))

(defun string->octets (string)
  (flexi-streams:string-to-octets
   string :external-format :utf-8))

(defun print-hex (x)
  (format t "~X " x))

(defun dump-array (a)
  (dotimes (i (array-total-size a))
    (print-hex (svref a i))
    (when (zerop (mod (1+ i) 8))
      (format t "~%")))
  (format t "~%"))


(defun dump-word-array-lisp (a)
  (for (i 0 (1- (array-total-size a)))
    (format t "#x~8,'0X " (aref a i))
    (when (zerop (mod (1+ i) 4))
      (format t "~%")))
  (values))

(defun dump-byte-array-lisp (a)
  (for (i 0 (1- (array-total-size a)))
    (format t "#x~2,'0X " (aref a i))
    (when (zerop (mod (1+ i) 8))
      (format t "~%"))))


(defun make-word (b3 b2 b1 b0)
  (declare (optimize (speed 3) (safety 0))
	   (type (unsigned-byte 8) b3 b2 b1 b0))
  (the (unsigned-byte 32)
    (logxor (the (unsigned-byte 32) (ash b3 24))
	    (the (unsigned-byte 32)
	      (logxor (the (unsigned-byte 32) (ash b2 16))
		      (the (unsigned-byte 32)
			(logxor (the (unsigned-byte 32) (ash b1 8))
				b0)))))))

(defun make-bytes (word byte-array offset)
  (for (i 0 3)
    (setf (aref byte-array (+ offset i))
	  (ldb (byte 8 (- 24 (* 8 i))) word))))

(defun make-word-from-byte-array (byte-array offset)
  (declare (optimize (speed 3) (safety 0))
  	   (type fixnum offset)
	   (type (array (unsigned-byte 8)) byte-array))
  (the (unsigned-byte 32)
    (make-word (aref (the (array (unsigned-byte 8) *) byte-array) offset)
	       (aref byte-array (1+ offset))
	       (aref byte-array (+ 2 offset))
	       (aref byte-array (+ 3 offset)))))

(defun make-byte-array-from-words (w0 w1 w2 w3 byte-array)
  (make-bytes w0 byte-array 0)
  (make-bytes w1 byte-array 4)
  (make-bytes w2 byte-array 8)
  (make-bytes w3 byte-array 12)
  byte-array)

(defun hex-string-to-byte-vector (string)
  (labels ((digit (x)
             (let ((code (char-code x)))
               (declare (type fixnum code))
               (cond ((and (<= code 57) (>= code 48))
                      (the fixnum (- code 48)))
                     ((and (>= code 97) (<= code 102))
                      (the fixnum (- code 87)))
                     ((and (<= code 70) (>= code 65))
                      (the fixnum (- code 55)))
                     (t (error "not a hexadecimal digit")))))
           (hex (a b)
             (+ (ash (digit a) 4) (digit b))))
    (let* ((len (floor (length string) 2))
           (vec (make-array len :element-type 'uint-8)))
      (dotimes (i len)
        (let ((tmp (* 2 i)))
          (setf (aref vec i)
                (hex (aref string tmp)
                     (aref string (1+ tmp))))))
      vec)))

(defun hex-vector-from-word-list (words)
  (let ((arr (make-array (* 4 (length words))
                         :element-type 'uint-8
                         :fill-pointer 0)))
    (dolist (x (if (consp words)
	           words (map 'list #'identity words)))
      (let ((tmp (make-array 4 :element-type 'uint-8)))
        (make-bytes x tmp 0)
        (dotimes (n 4)
          (vector-push (aref tmp n) arr))))
    arr))

(defun hex-string-from-word-list (words)
  (flet ((hex-char (x)
           (code-char
            (+ (if (< x 10)
                   #.(char-code #\0)
                   #.(- (char-code #\a) 10))
               x))))
    (with-output-to-string (str)
      (dolist (x (if (consp words)
                     words (map 'list #'identity words)))
        (let ((arr (make-array 4 :element-type 'uint-8)))
          (make-bytes x arr 0)
          (dotimes (n 4)
            (let* ((elt (aref arr n))
                   (first (ldb (byte 4 4) elt))
                   (second (ldb (byte 4 0) elt)))
            (write-char (hex-char first) str)
            (write-char (hex-char second)str))))))))

(defun byte-array-to-word-list (byte-array)
  (let ((num-words (/ (array-total-size byte-array) 4))
        (words nil))
    (dotimes (n num-words)
      (push (make-word-from-byte-array byte-array (* n 4)) words))
    (nreverse words)))

(defun byte-array-to-word-vector (byte-array)
  (declare (optimize (speed 3) (safety 0)))
  (let ((len (length byte-array)))
    (labels ((zaref (array offset)
               (if (< offset len)
                   (aref array offset) 0))
             (pull-word (bytes offset)
               (declare (type fixnum offset)
                        (type (vector uint-8) bytes))
               (the (unsigned-byte 32)
                 (make-word (zaref bytes offset)
                            (zaref bytes (+ offset 1))
                            (zaref bytes (+ offset 2))
                            (zaref bytes (+ offset 3))))))
      (let* ((num-words (ceiling (array-total-size byte-array) 4))
             (words (make-array num-words
                                :element-type 'uint-32
                                :fill-pointer 0)))
        (dotimes (n num-words)
          (vector-push (pull-word byte-array (* n 4))
                       words))
        words))))

(defun ensure-words (thing)
  "Return a word vector and an octet length if applicable."
  (etypecase thing
    (string
     (let ((octets (string->octets thing)))
       (values (byte-array-to-word-vector octets)
             (length octets))))
    ((vector uint-8 *)
     (values (byte-array-to-word-vector thing)
             (length thing)))
    ((vector uint-32 *) thing)))

(defun word-vector-to-byte-array (words)
  (let* ((len (length words))
         (bytes (make-array (* len 4) :element-type 'uint-8)))
    (dotimes (n len)
      (make-bytes (aref words n) bytes (* n 4)))
    bytes))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Copyright 2010 TSC AG, Postfach 73, CH 6314 Unterageri, Switzerland
;;;
;;; Licensed under the Apache License, Version 2.0 (the "License");
;;; you may not use this file except in compliance with the License.
;;; You may obtain a copy of the License at
;;;
;;;     http://www.apache.org/licenses/LICENSE-2.0
;;;
;;; Unless required by applicable law or agreed to in writing, software
;;; distributed under the License is distributed on an "AS IS" BASIS,
;;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;;; See the License for the specific language governing permissions
;;; and limitations under the License.
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

