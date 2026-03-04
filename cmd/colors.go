package cmd

import "github.com/fatih/color"

var (
	tagSent = color.New(color.FgGreen).SprintFunc()
	tagFail = color.New(color.FgRed).SprintFunc()
	tagSkip = color.New(color.FgYellow).SprintFunc()
	tagWait = color.New(color.FgYellow).SprintFunc()
	tagStop = color.New(color.FgRed).SprintFunc()

	cyan  = color.New(color.FgCyan).SprintFunc()
	green = color.New(color.FgGreen).SprintFunc()
)
