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

def checkTokens(record):
  points = 0
  dtCount = record["num_domain_tokens"]
  domainTokens = record["domain_tokens"]
  
  if dtCount > 3:
    points += (dtCount-3)
  
  for domain in domainTokens:
    length = len(str(domain))
    if str(domain).find("-") > 0:
      points += 3
    if length > 20:
      points += (length - 20)
  return points

def checkAlexa(record):
  alexa = record["alexa_rank"]  
  points = 0
  if alexa is not None:
    alexa = int(alexa)
    if alexa < 1000:
      points -= 5
    elif alexa < 10000:
      points -= 2
    elif alexa > 450000:
      points += 1
    elif alexa > 600000:
      points += 2

  return points

def checkAge(record):
  age = record["domain_age_days"]  
  points = 0
  if age is not None:
      age = int(age)
  
  if age < 10:
    points -= 15
  elif age < 30:
    points -= 5
  elif age < 365:
    points -= 3
  else:
    years = age / 365
    points += years
        
  return points

def checkMX(record):
  points = 0
  mxhosts = record["mxhosts"]
  
  if mxhosts is not None:
    for host in mxhosts:
      points += 1
      for ip in host["ips"]:
        points += 1
    print points
    return points
      
def checkGeo(record):
  countries = []
  points = 0
  ips = record["ips"]
  for ip in ips:
    geo = ip["geo"]
    if countries.count(geo) <= 0:
      countries.append(geo)
  mxhosts = record["mxhosts"] 
  if mxhosts is not None:
    for host in mxhosts:
      ips = host["ips"]
      for ip in ips:
        geo = ip["geo"]
        if countries.count(geo) <= 0:
          countries.append(geo)      
  if len(countries) > 1:
    print countries
    points += (2 * len(countries))
  return points


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


    rating += checkMX(record)    
    rating += checkAlexa(record)
    rating += checkAge(record)
    rating += checkGeo(record)
    rating += checkTokens(record)
    
    if malic:
      print "Rating: %d" % rating

    myFlag = 0
#     if rating < 0:
#       myFlag = 1

#     if myFlag and not malic:
#       falsepos += 1
#       falseMal.append((record,rating))
#     if myFlag and malic:
#       positives += 1
#     if malic and not myFlag:
#       missedMal.append((record,rating))
#       missed += 1
  corpus.close()

#   print "Positives: %d\nFalse Positives: %d\n Missed: %d" %(positives,falsepos,missed)
#   fn = 0
#   falseMal = []
#   for rec in missedMal:
#     fn += 1
#     print "Missed rec %d, rating %d" % (fn, rec[1])
#     print "Age: ",
#     print rec[0]["domain_age_days"]
#     print "Alexa: ",
#     print rec[0]["alexa_rank"]

if __name__ == "__main__":
  main(sys.argv[1:])
