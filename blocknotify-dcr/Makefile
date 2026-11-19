OUTPUT=blocknotify-dcr

all:
	go build -trimpath -o $(OUTPUT) .

install: all
	strip -s $(OUTPUT)
	killall -9 $(OUTPUT) || echo ok
	mv $(OUTPUT) ../bin/$(OUTPUT)

clean:
	rm -f $(OUTPUT)
