#!/usr/bin/python

import json, sys, getopt, os

def usage():
    print("Usage: %s --file=[filename]" % sys.argv[0])
    sys.exit()


def checkUp(record):
    flags = ["paypal","bank","credit"]
    status = 1
    for flag in flags:
        if str(record["url"]).find(flag) > 0:
            status = 0
    return status
def checkAlexa(alexa):
    rating = 0
    if alexa is not None:
        alexa = int(alexa)
        if alexa < 10000:
            rating += 50
        elif alexa < 25000:
            rating += 25
        elif alexa < 100000:
            rating += 10
        elif alexa < 250000:
            rating += 5
        elif alexa >= 500000:
            rating -= 3
        elif alexa >= 625000:
            rating -= 4
        elif alexa >= 700000:
            rating -= 5
    return rating

def checkAge(age):
    rating = 0
    if age is not None:
        age = int(age)
        if age < 0:
            rating -= 100
        elif age < 7:
            rating -= 20
        elif age < 30:
            rating -= 15
        elif age < 90:
            rating -= 10
        elif age < 180:
            rating -= 5
        elif age > 365:
            rating += 5
        elif age > 1825:
            rating += 50
    return rating

def main(argv):

    file=''
 
    myopts, args = getopt.getopt(sys.argv[1:], "", ["file="])
 
    for o, a in myopts:
        if o in ('-f, --file'):
            file=a
        else:
            usage()

    if len(file) == 0:
        usage()
 
    corpus = open(file)
    urldata = json.load(corpus, encoding="latin1")
    actualMal = []
    falseMal = []
    missedMal = []

    positives = 0
    missed = 0
    falsepos = 0


    for record in urldata:
        rating = 0
        malic = record["malicious_url"]
        if malic:
            actualMal.append(record)


        alexa = record["alexa_rank"]
        rating += checkAlexa(alexa)

        age = record["domain_age_days"]
        rating += checkAge(age)

        path = str(record["path"])
        if path.find(".exe") > 0:
            rating -= 50

        myFlag = 0
        if rating < 0:
            myFlag = 1
        
        if myFlag and not malic:
            falsepos += 1
            falseMal.append((record,rating))
        if myFlag and malic:
            positives += 1
        if malic and not myFlag:
            missedMal.append((record,rating))
            missed += 1
    corpus.close()
    
    print "Positives: %d\nFalse Positives: %d\n Missed: %d" %(positives,falsepos,missed)
    fn = 0
    falseMal = []
    for rec in missedMal:
        fn += 1
        print "Missed rec %d, rating %d" % (fn, rec[1])
        print "Age: ",
        print rec[0]["domain_age_days"]
        print "Alexa: ",
        print rec[0]["alexa_rank"]
        
if __name__ == "__main__":
    main(sys.argv[1:])
