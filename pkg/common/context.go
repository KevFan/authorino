package common

import (
	"context"
	"fmt"
)

// CheckContext checks if a go context is still active or done
// When it's done, returns a generic error
//
// func myFunc(ctx context.Context) error {
//   if err := common.CheckContext(ctx); err != nil {
//   	 return err
//   } else {
//     doSomething()
//   }
// }
func CheckContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("Context aborted")
	default:
		return nil
	}
}
