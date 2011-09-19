(in-package :cl-crypto)

(use-package :anaphora)

(defun pem-write (name data-string &key (stream *standard-output*))
  (format stream "-----BEGIN ~a-----~%~a~%-----END ~a-----~%"
	  name data-string name))

;;
;; EXTREMELY incomplete alist of Object Identifiers (see X.690 section 8.19)
;;
(defparameter *oid-alist*
  '(
    ((1) . :iso)
    ((1 2) . :member-body)
    ((1 2 840) . :iso-us)
    ((1 2 840 113549) . :rsa-dsi)
    ((1 2 840 113549 1) . :pkcs)
    ((1 2 840 113549 1 1) . :pkcs1)
    ((1 2 840 113549 1 1 1) . :rsaEncryption)
    ))

(defparameter *asn1-class-alist*
  '((#x00 . :universal)
    (#x01 . :application)
    (#x02 . :context-specifc)
    (#x03 . :private)))

(defparameter *asn1-p-or-c-alist*
  '((#x00 . :primitive)
    (#x01 . :constructed)))

;;
;; See http://www.obj-sys.com/asn1tutorial/node124.html for source.
;;
(defparameter *asn1-tag-alist*
  '((#x01 . :boolean)
    (#x02 . :integer)
    (#x03 . :bit-string)
    (#x04 . :octet-string)
    (#x05 . :null)
    (#x06 . :object-identifier)
    (#x07 . :object-descriptor)
    (#x08 . :external-instance)
    (#x09 . :real)
    (#x0a . :enumerated)
    (#x0b . :embedded-pdv)
    (#x0c . :utf8-string)
    (#x0d . :relative-oid)
    (#x0e . :undefined)
    (#x0f . :undefined)
    (#x10 . :sequence)
    (#x11 . :set)
    (#x12 . :numeric-string)
    (#x13 . :printable-string)
    (#x14 . :t61-string)
    (#x15 . :videotex-string)
    (#x16 . :ia-string)
    (#x17 . :utc-time)
    (#x18 . :generalized-time)
    (#x19 . :graphic-string)
    (#x1a . :iso646-string)
    (#x1b . :general-string)
    (#x1c . :universal-string)
    (#x1d . :character-string)
    (#x1e . :bmp-string)))

(defstruct asn1-data
  class
  p-or-c
  tag
  (header-length 0)
  (content-length 0)
  content
  child)

(defun get-length (stream)
  (aif (read-byte stream :eof-value nil)
       (let ((content-length 0)
	     (header-length 2))
	 (if (zerop (logand it #x80))
	     ;; Short form never sets high bit, so len <= 127
	     (setq content-length it)

	     ;; Long form always sets high bit, and can use multiple octets
	     (let ((num-octets (logand it #x7f)))
	       (incf header-length num-octets)
	       (setq content-length
		     (loop for i from (1- num-octets) downto 0
			sum (ash (read-byte stream) (* 8 i))))))
	 
	 ;; And return the results
	 (values header-length content-length))
       (error "EOF encountered when expecting LENGTH octet(s)")))
  

(defun get-header (stream)
  (aif (read-byte stream :eof-value nil)
       (let* ((class (cdr (assoc (ash it -6) *asn1-class-alist*)))
	      (p-or-c (cdr (assoc (logand (ash it -4) #x01) *asn1-p-or-c-alist*)))
	      (raw-tag (logand it #x1f))
	      (tag (cdr (assoc raw-tag *asn1-tag-alist*))))

	 ;; For now, not handling tags > 30
	 (assert (<= raw-tag 30) nil "TAG > 30 not yet implemented")
	 
	 (multiple-value-bind (header-length content-length)
	     (get-length stream)
	   (values class p-or-c tag header-length content-length)))
       (error "EOF encountered when expecting IDENTIFIER octet")))
       

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Example encoded Object Identifier for rsaEncryption (1 2 840 113549 1 1 1):
;;;
;;; See X.690 section 8.19.
;;;
;;; {joint-iso-itu-t 100 3} --> {2 100 3} --> #x813403
;;;
;;; To get the first 2 OIDs out of the (X * 40)) + Y thing:
;;; subids are a string of 7-bit quantities!  So: #x8134 is:
;;;
;;; (+ (ash (logand #x81 #x7F) 7) #x34) == 180 == #xB4 == 180.
;;;
;;; Then do (floor 180 40) => (4 20)
;;;
;;; Well, max for root value is 2, so we do this:
;;; First = 2, Second = (- 180 (* First 40))
;;; Result: First = 2, Second = 100.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun decode-first-second-subids (packed-input)
  "Decode a given integer into first and second subids as per X.690 8.19.4.
Returns (first second)"
  (multiple-value-bind (q r) (floor packed-input 40)
    (declare (ignore r))
    (let ((first-id (min q 2)))
      (values first-id (- packed-input (* first-id 40))))))


(defun get-num-additional-octets (array offset)
  "Returns number of octets in addition to that at (aref array offset)) making up the coded value starting at offset in array"
  (do ((i offset (1+ i))
       (len 0 (1+ len)))
      ((zerop (logand #x80 (aref array i))) len)))
    

(defun decode-number (array offset)
  "Decode a given encoded number spanning one or more octets in array.
Returns (value len) where value is the decoded number and len is the inclusive
number of octets that its encoded form required"
  (let* ((len (get-num-additional-octets array offset))
	 (acc
	  (do* ((i 0 (1+ i))
		(x (aref array (+ i offset)) (aref array (+ i offset)))
		(acc (ash (logand x #x7F) (* 7 (- len i)))
		     (+ acc (ash (logand x #x7F) (* 7 (- len i))))))
	       ((zerop (logand x #x80)) acc))))
    (values acc (+ 1 len))))


(defun parse-object-identifier (stream content-length)
  "Given an input stream set at the beginning of the object identifier data, and the
data length, parse the data into a list of decoded integer values"
  (let ((tmp-array (make-array content-length :element-type '(unsigned-byte 8))))
    (read-sequence tmp-array stream)
    (let* ((total-size (array-total-size tmp-array))
	   (acc nil)
	   (offset 0))

      ;; First number consistes of 2 packed subids
      (multiple-value-bind (value len)
	(decode-number tmp-array offset)
	(multiple-value-bind (first second)
	  (decode-first-second-subids value)

	  ;; Save both and inc offset
	  (push first acc)
	  (push second acc)
	  (incf offset len)

	  ;; Loop through the rest of the data
	  (when (> total-size offset)
	    (loop
	       do
		 (multiple-value-bind (value len)
		     (decode-number tmp-array offset)
		   (push value acc)
		   (when (>= (incf offset len) total-size)
		     (return nil)))))))
      (nreverse acc))))
	       


(defun dump-bytes-from-stream (stream content-length)
  (let ((tmp-array (make-array content-length :element-type '(unsigned-byte 8))))
    (read-sequence tmp-array stream)
    (format t "~%")
    (dump-byte-array-lisp tmp-array)))

(defun dump-header (class p-or-c tag header-length content-length)
  (format t "~%class: ~a, p-or-c: ~a, tag: ~a, header-length: ~a, content-length: ~a" class p-or-c tag header-length content-length))


(defun test ()
  (with-open-file (stream #P"~/tmp/pubkey.der"
			  :direction :input
			  :element-type '(unsigned-byte 8))
    ;; Get first one
    (multiple-value-bind (class p-or-c tag header-length content-length)
	(get-header stream)

      (dump-header class p-or-c tag header-length content-length)

      (let ((length-remaining content-length))

	(assert (equal (+ header-length content-length) (file-length stream))
		nil
		"Invalid LENGTH value")

	(loop
	   do
	     (when (zerop length-remaining) (return))
	     
	     (multiple-value-bind (class p-or-c tag header-length content-length)
		 (get-header stream)
	       (dump-header class p-or-c tag header-length content-length)
	       
	       (decf length-remaining header-length)
	       
	       (when (eq p-or-c :primitive)
		 (case tag
		   (:object-identifier
		    (let ((oid (parse-object-identifier stream content-length)))
		      (format t "~%~a"
			      (aif
			       (cdr (assoc oid *oid-alist* :test #'equal))
			       it
			       oid))))
		   (:bit-string
		    (dump-bytes-from-stream stream content-length))		       
		   (t
		    (dotimes (i content-length)
		      (read-byte stream))))
		 (decf length-remaining content-length))))
		 
	    
	))))

    
  
