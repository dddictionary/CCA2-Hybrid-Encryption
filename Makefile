SHELL = bash
main = readme
css = ""
extras := "-H csshead -H ../../../html/light.css -H cssfoot --filter pandoc-citeproc"
gmakefile := "../../pandoc_makefile"
pubdocs := $(wildcard ../*-skel.c ../*.h) \
	../prf.c \
	../Makefile \
	../.gitignore \
	../kem-test.sh \
	../test.sh \
	../examples/ \
	../tests/ \
	bad-code.jpg \
	readme.html
pubdir := /home/wes/repos/ccny/teaching/codearchives/csc480-projects/p1/
gradingdocs := $(wildcard ../*.c ../*.h) ../Makefile
gradingdir := /tmp/480grading

$(main).html: %.html: $(main).mkd csshead cssfoot
	make -f $(gmakefile) main=$(main) css=$(css) moreargs=$(extras)

csshead :
	echo '<style type="text/css">' >> csshead

cssfoot :
	echo "</style>" > cssfoot

.PHONY : pub
pub : $(pubdocs)
	mkdir -p $(pubdir)
	cp -r $(pubdocs) $(pubdir)
	for f in $(pubdir)/*-skel.c ; do mv $$f $${f/-skel.c/.c} ; done

grading : $(gradingdocs)
	mkdir -p $(gradingdir)
	cp $(gradingdocs) $(gradingdir)

.PHONY : clean
clean :
	rm -f csshead cssfoot readme.html
