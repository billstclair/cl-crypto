(in-package :cl-user)

(defun load-cl-crypto-files ()
  (dolist (file '("packages"
		  "types"
		  "utility"
		  "aes16"
		  "sha1"))
    (load file)))

(load-cl-crypto-files)
(use-package :cl-crypto)



