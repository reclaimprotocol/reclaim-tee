package main

// Note: All message types, constants, data structures, and helper functions
// have been consolidated into the shared package (shared/types.go).
//
// The client now uses:
// - shared.MessageType for message type constants
// - shared.Message for the base message structure
// - shared.CreateMessage() for creating messages
// - shared.ParseMessage() for parsing messages
// - shared.*Data structs for all data structures
//
// This consolidation removed ~200 lines of exact duplicates while preserving
// all functionality through the shared package interface.
