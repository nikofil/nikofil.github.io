---
title: "First month of GSoC 2017"
author: "Nikos Filippakis"
tags: go go-dpi gsoc
---

The first month of my Google Summer of Code is already coming to an end, and the Phase 1 evaluation is also around the corner, which coincidentally is also the last week of my contract at CERN. With that in mind, this seems like a good time to write a blog post about the project and my progress during the first month.

While looking for a project to apply for, I was browsing the Security-related projects when I found an organization that I admittedly didn't know but that had many interesting projects that I've used or heard of before, called the Honeynet Project. Their very first project idea especially caught my eye: A new project, to be created in Go, that would identify protocols from packets as they arrived on the wire, in order for a honeypot server to be able to tell which protocol it is from the first packet. The implementation itself could be very open-ended: One could use machine learning, heuristics, make a rule-based system or copy what other libraries similar do.

At first I believed this project would have many people applying and thought my chances wouldn't be good, as I would also be working during the first month, but I decided to apply anyway hoping to learn a new language and try to apply machine learning to such a different concept and see what comes out. Eventually, after my application, I was given a small project to try and complete in Go by my prospective supervisor and, after setting it up and learning enough Go to get it to work, I was offered the project. For this, I am very grateful to my supervisor, Lukas Rist, as well as for his assistance while working on this project.

## Project planning
During the community bonding period I had an idea of how I wanted the project to look like and the structure I would like to go for. I thought that would be a good time to create some diagrams to communicate my ideas to my supervisor as there wasn't much else I could do during that period: As I was going to create a new project, I had no existing code base to get familiar with, except for reading the docs of similar libraries that could eventually be used inside the project, such as [nDPI](https://github.com/ntop/nDPI/), [libprotoident](https://research.wand.net.nz/software/libprotoident.php) and [AIEngine](http://aiengine.readthedocs.io/en/latest/aiengine.html). I created the diagrams using <https://draw.io>, which made the process rather painless, and eventually shared them with my supervisor. They can now be found in the project wiki, at [Workflow diagrams](https://github.com/mushorg/go-dpi/wiki/Workflow-diagrams).

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

The current implementation of the library has the basic project structure down. The library exposes a simple API and classifies flows based on heuristics and wrappers. Most heuristics though are using only the ports used by the packets, so they will be redone soon in order to be port-independent. Instead, during the first month the wrappers were developed for the nDPI and libprotoident libraries. This way, while still in an early phase, the library should hypothetically offer at least the benefits of these two libraries.

## Library example

The library and the modules APIs aim to be very simple and straightforward to use. The library relies on the [gopacket](https://godoc.org/github.com/google/gopacket) library and its Packet structure. Once you have a Packet in your hands, it's very easy to classify it with the library.
First you need a flow that contains the packet. There is a helper function for constructing a flow from a single packet. Simply call:

```go
flow := godpi.CreateFlowFromPacket(&packet)
```

Afterwards, classifying the flow can be done by simply calling:

```go
proto, source := classifiers.ClassifyFlow(flow)
```

This returns the guess protocol by the classifiers as well as the source (which in this case will always be go-dpi).

The same thing applies for wrappers. However, for wrappers you also have to call the initialize function, and the destroy function before your program exits. All in all, the following is enough to run the wrappers:

```
wrappers.InitializeWrappers()
defer wrappers.DestroyWrappers()
proto, source = wrappers.ClassifyFlow(flow)
```

A minimal example application is included below. It uses both the classifiers and wrappers to classify a simple packet capture file. Note the helpful `godpi.ReadDumpFile` function that simply returns a channel with all the packets in the file.

```
package main

import "fmt"
import "github.com/mushorg/go-dpi"
import "github.com/mushorg/go-dpi/classifiers"
import "github.com/mushorg/go-dpi/wrappers"

func main() {
	packets, err := godpi.ReadDumpFile("/tmp/http.cap")
	wrappers.InitializeWrappers()
	defer wrappers.DestroyWrappers()
	if err != nil {
		fmt.Println(err)
	} else {
		for packet := range packets {
			flow := godpi.CreateFlowFromPacket(&packet)
			proto, source := classifiers.ClassifyFlow(flow)
			if proto != godpi.Unknown {
				fmt.Println(source, "detected protocol", proto)
			} else {
				fmt.Println("No detection made by classifiers")
			}
			proto, source = wrappers.ClassifyFlow(flow)
			if proto != godpi.Unknown {
				fmt.Println(source, "detected protocol", proto)
			} else {
				fmt.Println("No detection made by wrappers")
			}
		}
	}
}
```

Running this application (when you have the http.cap file in your /tmp folder) yields the following results:

```
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
libprotoident detected protocol HTTP
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
libprotoident detected protocol HTTP
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol DNS
libprotoident detected protocol DNS
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol DNS
nDPI detected protocol DNS
go-dpi detected protocol HTTP
libprotoident detected protocol HTTP
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
libprotoident detected protocol HTTP
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
libprotoident detected protocol HTTP
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
go-dpi detected protocol HTTP
No detection made by wrappers
```

The reason go-dpi is able to detect every single packet is because it uses port numbers, which won't be allowed in the future.

The example app also nicely demonstrates the library. You can read about it [here](https://github.com/mushorg/go-dpi/wiki/Example-app), or read about the dockerized version [here](https://github.com/mushorg/go-dpi/wiki/Docker-image).

## Results

As the integration with the glutton honeypot isn't working yet, for the testing of the library mostly the [sample captures from the Wireshark](https://wiki.wireshark.org/SampleCaptures) site were used. Live capture from a device was also supported, but it's easier to test for a specific protocol by using the appropriate capture file.

Using the example app, we can see both the classifications based on the heuristics (which should be right most of the time, as they currently use ports which won't be the case when the library is finished) and on the wrappers. Since the wrappers are utilizing mature and well-established libraries, we would expect that they should work in most of the cases. While the wrappers do usually work, they have varying degrees of success with the different protocols. The status of the currently supported protocols are described below:

* **DNS, HTTP, ICMP, NetBIOS, SSL/TLS**  
  These protocols are identified normally by the wrappers from the first request, at least in the tested cases. :)

* **FTP**  
  The protocol is detected from the first client-sent packet (besides the TCP handshake). However, the server is first supposed to send a packet with the code 220, which means the service is ready. So we can't really use this to guess that it's an FTP connection on a live capture, before responding to it.

* **SMTP**  
  Similar to FTP, it gets detected but the server must also send a packet with code 220, which is problematic if the library is used to understand the connection before sending a packet. Also sometimes it gets confused for POP3 instead by libprotoident.

* **SMB**  
  Sometimes the flows do not get detected, by either nDPI or libprotoident. Also, sometimes classified as NetBIOS instead (as it runs over NetBIOS).

* **RDP**  
  Neither wrapper seems to detect RDP in any of the dumps I found. Might be because it's over COTP, which is over TPKT, two protocols I've never heard of before.

* **RPC**  
  Same with the RDP protocol, neither wrapper seems to identify this. However I don't know how either of these protocols work, so I need to dig deeper on this.

## Plans for the future

With the wrappers mostly out of the way, the next task will be to focus on homemade classifiers for each protocol: This will be done first by creating heuristics, and then if it's feasible by using machine learning. The heuristics should hopefully cover the weaknesses found on the wrappers in order to have a more complete library. Also, they should generally be faster than deferring the work to a library. Machine learning on the other hand might inherit the weaknesses of the captures that will be used for training, so for the protocols where there isn't enough data available it might not lead to good results.

There is also the challenge of the detection of tunneled protocols over SSL, such as HTTPS. In order to detect HTTPS, we will probably have to first classify a flow as SSL and once the handshake is over figure out about the protocol underneath and classify it as the more specific HTTPS. It's not clear yet if the structure of the project will need to change to support this.

Another possible task for the future could be the tracking of flows. Currently, each packet is treated and classified as a separate flow, in order to make it possible in the future to easily have more packets per flow. We will have to think however what the benefits of that would be for the heuristic classifiers, as the current nDPI wrapper implementation supports flows on its own and it will probably be hard to train the ML classifiers on flows instead of single packets.

Finally, there is the task of improving the processing time and parallelization of the library, which we haven't looked into at all yet, in order to be capable to deal with as many packets as possible at a time.
