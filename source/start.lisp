(in-package :cl-user)

(defun load-cl-crypto-files ()
  (dolist (file '("packages"
		  "types"
		  "macros"
		  "aes16"
		  "sha1"
                  ;; Need cl-base64 & flexi-streams for this file
                  ;;"strings"
                  ))
    (load file)))

(load-cl-crypto-files)
(use-package :cl-crypto)



