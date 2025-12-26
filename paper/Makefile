.PHONY: all clean

all: lamport.pdf

lamport.pdf: lamport.tex
	pdflatex lamport.tex
	pdflatex lamport.tex

clean:
	rm -f *.aux *.log *.out *.toc *.pdf
