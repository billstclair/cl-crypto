(in-package :cl-crypto)

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

(defmacro rot-byte-R ()
  "Byte roation to the right"
  ;; This is a macro since it is called when making constants
  (let ((word (gensym)))
    `(lambda (,word) 
      (logxor (ash (ldb (byte 8 0) ,word) 24)
       (ash ,word -8)))))

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
