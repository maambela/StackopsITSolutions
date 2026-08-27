# Use the official lightweight Node.js 20 image as the base image for the build stage.
# We recommend using a specific major version (like 20-slim) for stability.
FROM node:24-bookworm-slim as builder

# Create and set the working directory for the application
WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*


# Copy package.json and package-lock.json (if you have one) to the workdir.
# We do this first to leverage Docker's build cache when dependencies don't change.
COPY package*.json ./

# Install application dependencies
RUN npm install --omit=dev

# Copy the rest of the application source code (server.js, html, etc.)
COPY . .

# Cloud Run requires the container to listen on the port specified by the PORT environment variable.
# Your code (server.js) already uses process.env.PORT || 8080, so exposing 8080 is a standard practice.
EXPOSE 8080

# Run the app. The 'start' script from package.json will be executed.
CMD [ "npm", "start" ]