// This function sets up auth headers for each test in the current test group.
export default () => {
    const token = Cypress.env('ROX_AUTH_TOKEN');
    if (token) {
        beforeEach(() => {
            cy.intercept('*', {
                headers: {
                    Authorization: `Bearer ${token}`,
                },
            });
        });
    }
};
