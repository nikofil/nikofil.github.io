---
layout: post
title: "First month of GSoC 2017"
tags: go go-dpi gsoc
---

The first month of my Google Summer of Code is already coming to an end, and the Phase 1 evaluation is also around the corner, which coincidentally is also the last week of my contract at CERN. With that in mind, this seems like a good time to write a blog post about the project and my progress during the first month.

While looking for a project to apply for, I was browsing the Security-related projects when I found an organization that I admittedly didn't know but that had many interesting projects that I've used or heard of before, called the Honeynet Project. Their very first project idea especially caught my eye: A new project, to be created in Go, that would identify protocols from packets as they arrived on the wire. The implementation itself could be very open-ended: One could use machine learning, heuristics, make a rule-based system or copy what other libraries similar do.

At first I believed this project would have many people applying and thought my chances wouldn't be good, as I would also be working during the first month, but I decided to apply anyway hoping to learn a new language and try to apply machine learning to such a different concept and see what comes out. Eventually, after my application, I was given a small project to try and complete in Go by my prospective supervisor and, after setting it up and learning enough Go to get it to work, I was offered the project. For this, I am very grateful to my supervisor, Lukas Rist, as well as for his assistance while working on this project.

## Project planning

During the community bonding period I had an idea of how I wanted the project to look like and the structure I would like to go for. I thought that would be a good time to create some diagrams to communicate my ideas to my supervisor as there wasn't much else I could do during that period: As I was going to create a new project, I had no existing code base to get familiar with, except for reading the docs of similar libraries that could eventually be used inside the project, such as [nDPI](https://github.com/ntop/nDPI/), [libprotoident](https://research.wand.net.nz/software/libprotoident.php) and [AIEngine](http://aiengine.readthedocs.io/en/latest/aiengine.html). I created the diagrams using <draw.io>, which made the process rather painless, and eventually shared them with my supervisor. They can now be found in the project wiki, at [Workflow diagrams](https://github.com/mushorg/go-dpi/wiki/Workflow-diagrams).

The project structure that we decided to go with was that the project would have many layers of classifiers. All of them would have the same purpose: Given a traffic flow (a collection of packets that belong to the same connection or "conversation"), try to guess the protocol for that flow. The difference would be how this classification happens and, hopefully, how much time each layer takes. So if the first, fast layer is not sure about a flow, the second one is used, etc.  
Each layer resides in a different directory in the project and is independent from the other layers, though they should generally follow an interface for the APIs they expose. This should allow additional layers to be added easily, and for the user to choose a subset of layers to use. The planned layers are the following:
* **Heuristics**  
  The simplest and fastest layer, it aims to have different heuristic methods to detect each protocol.
* **Wrappers**  
  Wrappers for other libraries that do a similar job.
* **Machine learning**  
  ML classifier trained on existing pcap dumps.

## Setting up the project

As I had set up the trial project shortly before my actual GSoC project, setting it up was easy: I already knew how to publish the docs on godoc, how to use travis and coveralls and how a Go project structure should be in general. Coveralls in specific seemed a bit tricky to setup, as there is no official support for the Go language in coveralls, but the user-contributed [goveralls](https://github.com/mattn/goveralls) was there to make things easy. Besides that, I also decided to use [glide](https://github.com/Masterminds/glide) for managing the packages that the project depends on, as I saw that [glutton](https://github.com/mushorg/glutton), the honeypot project that my library would eventually be integrated into, was also using glide.

For more information about the set up of the project you may see the docs at <https://godoc.org/github.com/mushorg/go-dpi>. Also, there is a wiki that describes usage and development for the library at <https://github.com/mushorg/go-dpi/wiki>.

## Current implementation

TODO

## Results

TODO

## Things learned

TODO

## Plans for the second month

TODO
