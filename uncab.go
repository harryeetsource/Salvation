package main

import (
	"fmt"
	"os/exec"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

func main() {
	a := app.New()
	w := a.NewWindow("CAB Extractor")
	w.SetFixedSize(false)

	var inputFile, outputDir string

	inputButton := widget.NewButton("Select CAB file", nil)
	outputButton := widget.NewButton("Select Output Directory", nil)
	extractButton := widget.NewButton("Extract", nil)

	inputButton.OnTapped = func() {
		fd := dialog.NewFileOpen(func(file fyne.URIReadCloser, err error) {
			if err == nil && file != nil {
				inputFile = file.URI().String()
				inputButton.SetText(inputFile)
			}
		}, w)
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".cab"}))
		fd.Resize(fyne.NewSize(800, 600)) // Set custom size for the file dialog
		listableURI, err := storage.ListerForURI(storage.NewFileURI("C:/"))
		if err == nil {
			fd.SetLocation(listableURI) // Set the initial directory (example: C:/)
		}
		fd.Show()
	}

	outputButton.OnTapped = func() {
		dd := dialog.NewFolderOpen(func(dir fyne.ListableURI, err error) {
			if err == nil && dir != nil {
				outputDir = dir.String()
				outputButton.SetText(outputDir)
			}
		}, w)
		dd.Resize(fyne.NewSize(800, 600)) // Set custom size for the folder dialog
		listableURI, err := storage.ListerForURI(storage.NewFileURI("C:/"))
		if err == nil {
			dd.SetLocation(listableURI) // Set the initial directory (example: C:/)
		}
		dd.Show()
	}

	extractButton.OnTapped = func() {
		if inputFile == "" || outputDir == "" {
			dialog.ShowError(fmt.Errorf("Please select a CAB file and output directory before extracting."), w)
			return
		}

		// Remove the "file://" prefix from the inputFile and outputDir
		inputFile = strings.TrimPrefix(inputFile, "file://")
		outputDir = strings.TrimPrefix(outputDir, "file://")

		cmd := exec.Command("expand", inputFile, "-F:*", outputDir)
		fmt.Printf("Executing command: %s\n", cmd.String())

		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Error output: %s\n", string(output))
			dialog.ShowError(fmt.Errorf("Extraction failed: %v", err), w)
		} else {
			dialog.ShowInformation("Success", "Extraction completed successfully!", w)
		}
	}
	content := container.NewGridWithColumns(1, inputButton, outputButton, extractButton)
	w.SetContent(content)
	w.Resize(fyne.NewSize(800, 200))
	w.ShowAndRun()
}
