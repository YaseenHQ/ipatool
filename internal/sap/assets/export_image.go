package assets

import "fmt"

// ExtractImage exports the named shared-cache image to destination. It mirrors
// ExtractAuthenticationPlugin for arbitrary images.
func (s *StoreCache) ExtractImage(imagePath, destination string) error {
	if err := s.ctx.Err(); err != nil {
		return fmt.Errorf("extract image %s: %w", imagePath, err)
	}

	return extractDyldImageFromFiles(s.opener, imagePath, destination)
}
