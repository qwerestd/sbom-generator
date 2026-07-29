module example.com/service-b

go 1.22

require github.com/example/lib/v2 v2.3.0

replace github.com/example/lib/v2 v2.3.0 =>
    github.com/example/libfork/v2 v2.3.1
