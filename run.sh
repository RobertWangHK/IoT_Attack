c=1
while [ $c -le 20 ]
do
	python capture.py
	(( c++ ))
done
