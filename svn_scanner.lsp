#!/usr/bin/newlisp
#######################################################
# @module svn scanner (svn 扫描器)
# @author 黄登(winger)
# @version 0.1
# @location https://github.com/freewinger/wsec_toolkit/
# @gtalk free.winger@gmail.com
# @gtalk-Group zen0code@appspot.com
# @blog http://my.opera.com/freewinger/blog/
# @qq-group 31138659
# 大道至简 -- newLISP
# Copyright 2013 黄登(winger) All rights reserved.
# Licensed under GNU GPL V3 
########################################################

###thie script have a bug on get-url###

(define (get-arg argname )
    (let (ix (find argname (main-args)))
        (and ix (main-args (inc ix)))
    )
)

(set 'VER [text]
    Svn scanner v0.1
    auth: winger [FL]
    mail: free.winger at gmail.com
    ex: newlisp svnscan.lsp \r\n
    ex: newlisp svnscan.lsp -h \r\n
    ex: newlisp svnscan.lsp  [-n 25 -ts 1000 -f ip.txt  -p path.txt  -r result.html ]
    
[/text]
)
(define (usage)
    (print VER)
)
;(usage)
(if (find "-h" (main-args)) (and (usage) (exit)))



(set 'starttime     (date-value))
(set 'pnum          (or (int  (get-arg "-n")) 10))
(set 'TIMEOUT       (or (int (get-arg "-ts")) 1000))
(set 'TIMEOUT2       (or (int (get-arg "-th")) 5000))
(set 'fip             (or (get-arg "-f") "ip.txt"))
(set 'fresult        (or (get-arg "-r") (string "svnscan_result" (date starttime 0 "%x%X") ".html")))
(set 'fpath          (or (get-arg  "-p") "path.txt"))
(set 'supermode (find "-sc" (main-args))) ;scan C network section 
(set 'FID_R         (open fresult "append"))
(set 'pcount 0)
;;;!!!!!!!!!!!!!此处记得一定要有: 和\r\n. 否则不符合http头标准!!!!! MUST END WITH "\r\n"
(set 'AGENT  "User-AGENT:	Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.2.13) Gecko/20110504 Firefox/3.6.13\r\n")

(set 'AGENT (or (get-arg  "-a") AGENT))

;(set 'portlst (list "80"))
;(set 'portlst (list "80" "8000" "8080"))
;(set 'portlst (list "80"  "808" "8000"  "8001" "8002" "8003" "8008"  "8010" "8080"    "8081"  "8088"  "8090" "8181"))
(set 'portlst (list "80" "808" "8000" "8001" "8002" "8003" "8008" "8010" "8080" "8081" "8088" "8090" "8181" "81" "82" "88" "99" "8004" "8005" "8006" "8007" "8009" "8011" "8082" "8083" "8099" "8100" "8200" "8899" "9998" "9999"))


(set 'ALLPATH (parse (read-file fpath) {\r\n|\n|\r} 0))
(set 'ALLPATH '(".svn" "_svn" "index.php.bak" ""))
(set 'FOOLCHECK "/%01")
(set 'DEADTIME  4000)
 
(define (brute_path host , url url2 result str  socket)
            (if-not (starts-with host "http://") (setf url2  (string "http://" host)))
            (dolist (port portlst)
                (when (and 
                      	(setf socket (net-connect host (int port) TIMEOUT))
                      	(close socket);must new line
                        ;;;### get-url can't return sometimes even if you use timeout parameter ###
                       	(find "^ERR: server code 404" (get-url (append url2 ":" port FOOLCHECK)  TIMEOUT2) 1)
                       )
                      (dolist (path ALLPATH)
                            (setf url (append url2 ":" port  path));notice here 
                            ;(setf result (get-url url  "list debug" TIMEOUT AGENT))
                            (setf result (get-url url  TIMEOUT AGENT))
                            (if-not (find "^ERR: Operation timed out" result 1)
                                (if-not (find "^ERR.*\n*" result 1)
                                    (and
                                    (println "\r\n\r\n----------------------Bingo----------------------\r\n" url "\r\n")
                                    (set 'str  (string  "<a href=\"" url " \">" url "</a>        200 </br>"))
                                    (write FID_R  str)
                                    )
                                   ; (
                                    ;can add other err log ex:503 forbiden
                                    ;)
                              )
                              (and
                                (println "\r\n\r\n----------------------Time out----------------------\r\n" url "\r\n")
                                (set 'str  (string  "<a href=\"" url "\">" url "</a>        time out </br>"))
                                (write FID_R  str)
                              )
                        	)
                    ) 

                )
            )
)

(define (buildiplst iplst , (lst '()) (ipclst '()))
    (dolist (ipc iplst)
        (set 'ipc (join (chop (parse ipc ".") )".")) 
        (if-not (find ipc ipclst)
            (begin
            (extend lst (map (fn (n) (string ipc "." n)) (sequence 1 255)))
            (push ipc ipclst))
        )
    )
    lst
)

(println "\nGo? (y/n)")
(if (= (read-key) "n")
    (begin (usage) (exit))
)

(write FID_R "<h1 align=\"center\">-------------------------Svn Scan Result-------------------------</h1><h3 align=\"center\">-------------------------winger-------------------------</h3></br></br></br>")

(set 'allipc  (clean null? (parse (read-file fip) {(\r\n|\n|\r)+} 0) ))
(randomize allipc)
;;;following ipc just for test , commit thoes  if you want to customize the parameters by command line.
(setf allipc '("74.125.31.1" "74.125.32.1" "74.125.30.1" "74.125.33.1" "74.125.34.1" "74.125.35.1" "74.125.36.1" "74.125.37.1"))
(if supermode 
        (set 'allip (randomize(buildiplst allipc)))
        (set 'allip  allipc)
)

(set 'allipnum (length allip))
(println "Begin Dig " allipnum " IP!!! \nUse " pnum  " Process!!!\nGood Luck!")

(set 'sid (semaphore))
(semaphore sid 1)


(set 'pnum (min pnum allipnum))
;(println pnum)
;(println allip)
;(exit)
 (dotimes (n pnum)
    (spawn (sym (allip pcount)) (brute_path  (allip pcount)))
    (inc pcount)
    (println "")
)

(define (report pid)
    (semaphore sid -1)
    (when (< pcount allipnum)
        (spawn (sym (allip  pcount)) (brute_path (allip pcount)))
    )
    (inc pcount)
    (semaphore sid 1)
)

(until (sync 3000 report)  (print ".")) ;;;### have use sync --!###
(println "Begin process scan result")
(close FID_R)
(set 'endtime (date-value))
(set 'alltime (- endtime starttime))
(define (phour s) (/ s (pow 3600 2)))
(define (pminute s) (/ (mod s (pow 3600 2)) 60))
(define (psecond s) (mod (mod s (pow 3600 2)) 60))
(println "\r\nSpend "(phour alltime) " " (pminute alltime) " minutes "  (psecond alltime) " seconds ")
(println "\r\nResult file: " fresult)
(exec (append "firefox " fresult ))
(exit)